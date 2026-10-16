//! v1.5.1 P2-05 / S151-29: the `postgresql_role` resource against a scripted
//! PostgreSQL server (`FakePostgres`): plan / apply / audit, idempotence,
//! drift, only-declared attributes, the SCRAM verifier kept out of argv and
//! every report surface, the log-suppression gate, and fail-closed handling.
//! The real-server behavior (PostgreSQL 10 / 13 / 16 / 17 on Rocky Linux
//! 8 / 9 / 10, server-log canary scan) is verified on real hosts in Phase 2.

mod common;

use common::*;
use sinter::audit::{AuditReport, AuditResourceStatus};
use sinter::engine::{AggregateStatus, Engine, Mode, RunOptions, RunReport, TargetSpec};
use sinter::error::SinterError;
use sinter::executor::FakeTarget;
use sinter::fakesys::{FakePgRole, FakePostgres};
use sinter::model::load_model;
use sinter::output::{OutputFormat, RenderOptions};
use sinter::result::{Change, DiffBody, Execution, Verification};
use sinter::secret_source::{ProcessSecrets, SharedSecrets};
use sinter::secrets::{self};
use sinter::secrets_cli::{Env, Prompter};
use std::cell::RefCell;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::rc::Rc;

/// Synthetic verifiers (well-formed, never a real password's).
fn verifier(seed: char) -> String {
    let k: String = std::iter::repeat_n(seed, 43).collect();
    format!("SCRAM-SHA-256$4096:Q0FOQVJZLXNhbHQtdjE1MQ==${k}=:{k}=")
}

struct Quiet(Rc<RefCell<Vec<u8>>>);
impl Write for Quiet {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
struct NoTty;
impl Prompter for NoTty {
    fn interactive(&self) -> bool {
        false
    }
    fn read_secret(&mut self, _p: &str) -> std::io::Result<zeroize::Zeroizing<String>> {
        Err(std::io::ErrorKind::UnexpectedEof.into())
    }
    fn read_line(&mut self, _p: &str) -> std::io::Result<String> {
        Err(std::io::ErrorKind::UnexpectedEof.into())
    }
}

struct Fx {
    dir: PathBuf,
    key: PathBuf,
    recipient: secrets::Recipient,
}

fn fx(label: &str) -> Fx {
    let dir = trusted_root(label);
    std::fs::create_dir_all(dir.join("secrets")).unwrap();
    let id = secrets::generate_identity();
    let key = dir.join("key.txt");
    std::fs::write(&key, id.identity_file.expose()).unwrap();
    set_mode(&key, 0o600);
    Fx {
        key,
        recipient: id.recipient,
        dir,
    }
}

impl Fx {
    fn put(&self, name: &str, plain: &[u8]) {
        let ct =
            secrets::encrypt_to_recipients(plain, std::slice::from_ref(&self.recipient)).unwrap();
        std::fs::write(self.dir.join("secrets").join(name), ct).unwrap();
    }
    fn src(&self) -> SharedSecrets {
        Rc::new(RefCell::new(ProcessSecrets::new(
            Env {
                identity_env: Some(self.key.clone().into_os_string()),
                xdg_config_home: None,
                home: Some(self.dir.join("home")),
                cwd: self.dir.clone(),
                euid: unsafe { libc::geteuid() },
            },
            Box::new(NoTty),
            Box::new(Quiet(Rc::new(RefCell::new(Vec::new())))),
        )))
    }
    fn recipe(&self, body: &str) -> PathBuf {
        write_recipe(
            &self.dir,
            "r.yaml",
            &format!("version: 1\nresources:\n{}", body),
        )
    }
    /// A role `app` with `extra` fields and the verifier secret.
    fn role(&self, extra: &str) -> PathBuf {
        self.recipe(&format!(
            "  - id: role\n    type: postgresql_role\n    with:\n      name: app\n      password_verifier: {{ secret: secrets/app.age }}\n{extra}"
        ))
    }
}

fn target(server_version: u32) -> FakeTarget {
    let mut t = FakeTarget::rocky9().with_group("postgres", 26).with_user(
        "postgres",
        26,
        26,
        "/var/lib/pgsql",
        "/bin/bash",
    );
    t.pg = FakePostgres::running(server_version);
    t
}

fn engine(
    r: &Path,
    mode: Mode,
    sudo: bool,
    src: Option<SharedSecrets>,
    t: FakeTarget,
) -> Result<Engine, SinterError> {
    let e = Engine::new(
        load_model(r)?,
        RunOptions {
            mode,
            sudo,
            target: TargetSpec { ssh: None },
            verbose: false,
            fault: None,
            fake_target: Some(t),
        },
    )?;
    Ok(match src {
        Some(s) => e.with_secrets(s),
        None => e,
    })
}

/// Run and hand back the server state the run left (the fake moves into the
/// engine, so the state is read back from the shared script log's target).
fn run(r: &Path, mode: Mode, f: &Fx, t: &mut FakeTarget) -> Result<RunReport, SinterError> {
    let e = engine(r, mode, true, Some(f.src()), t.clone())?;
    let rep = e.run()?;
    if let Some(after) = &rep.fake_pg {
        t.pg.roles = after.roles.clone();
    }
    Ok(rep)
}

fn audit(r: &Path, f: &Fx, t: &FakeTarget) -> AuditReport {
    sinter::audit::run_audit(engine(r, Mode::Plan, true, Some(f.src()), t.clone()).unwrap())
        .unwrap()
}

fn surfaces(rep: &RunReport, mode: &str) -> Vec<String> {
    let mut v = Vec::new();
    for fmt in [OutputFormat::Text, OutputFormat::Json] {
        let ro = RenderOptions {
            verbose: true,
            format: fmt,
            color: false,
        };
        let mut b = Vec::new();
        if mode == "plan" {
            sinter::output::render_plan(rep, &ro, &mut b).unwrap();
        } else {
            sinter::output::render_apply(rep, &ro, &mut b).unwrap();
        }
        v.push(String::from_utf8_lossy(&b).to_string());
    }
    v.push(sinter::output::run_report_json(rep, mode).to_string());
    v.push(format!("{:?}", rep.resources));
    v.push(format!("{:?}", rep.commands));
    v
}

fn audit_surfaces(rep: &AuditReport) -> Vec<String> {
    vec![
        rep.render_text(),
        sinter::output::audit_report_json(rep).to_string(),
        format!("{:?}", rep.resources),
    ]
}

/// The verifier (and its keys) appears on no surface.
fn clean(v: &str, texts: &[String]) {
    let key = v.rsplit(':').next().unwrap();
    for t in texts {
        assert!(!t.contains(v), "leaked the verifier: {t}");
        assert!(!t.contains(key), "leaked a verifier key: {t}");
        assert!(
            !t.contains("Q0FOQVJZLXNhbHQtdjE1MQ"),
            "leaked the salt: {t}"
        );
    }
}

/// psql invocations the server saw: (argv, stdin).
fn psql_calls(t: &FakeTarget) -> Vec<(Vec<String>, Option<String>)> {
    t.pg.scripts.lock().unwrap().clone()
}

fn res(rep: &RunReport) -> &sinter::result::ResourceResult {
    find(rep, "role")
}

// ---------------------------------------------------------------------------
// convergence
// ---------------------------------------------------------------------------

#[test]
fn creates_the_role_then_converges_on_every_supported_server_version() {
    for ver in [100_023, 130_023, 160_015, 170_011] {
        let f = fx("pgrole-create");
        let v = verifier('A');
        f.put("app.age", format!("{v}\n").as_bytes());
        let r = f.role("      login: true\n      connection_limit: 20\n");
        let mut t = target(ver);

        let plan = run(&r, Mode::Plan, &f, &mut t).unwrap();
        assert_eq!(res(&plan).change, Change::Changed, "{ver}");
        assert!(matches!(
            res(&plan).diff.as_ref().unwrap().body,
            DiffBody::Redacted
        ));

        let apply = run(&r, Mode::Apply, &f, &mut t).unwrap();
        assert_eq!(
            apply.status,
            AggregateStatus::Success,
            "{:?}",
            res(&apply).reason
        );
        assert_eq!(res(&apply).change, Change::Changed);
        assert_eq!(res(&apply).verification, Verification::Verified);
        let role = t.pg.roles.get("app").expect("created");
        assert!(role.attrs[0], "login");
        assert!(!role.attrs[1], "never superuser unless declared");
        assert_eq!(role.conn_limit, 20);
        assert_eq!(role.password.as_deref(), Some(v.as_str()));

        let again = run(&r, Mode::Apply, &f, &mut t).unwrap();
        assert_eq!(res(&again).change, Change::None, "{ver}: second apply");
        let a = audit(&r, &f, &t);
        assert_eq!(
            a.resources[0].status,
            AuditResourceStatus::Compliant,
            "{ver}"
        );

        for (rep, mode) in [(&plan, "plan"), (&apply, "apply"), (&again, "apply")] {
            clean(&v, &surfaces(rep, mode));
        }
        clean(&v, &audit_surfaces(&a));
    }
}

/// The verifier reaches psql only on standard input, inside the verified
/// quiet gate; no argv ever carries it.
#[test]
fn the_verifier_travels_only_on_stdin_after_the_quiet_gate() {
    let f = fx("pgrole-stdin");
    let v = verifier('B');
    f.put("app.age", v.as_bytes());
    let r = f.role("      login: true\n");
    let mut t = target(170_011);
    run(&r, Mode::Apply, &f, &mut t).unwrap();
    let calls = psql_calls(&t);
    let mut changes = 0;
    for (argv, stdin) in &calls {
        assert!(
            !argv.iter().any(|a| a.contains(&v)),
            "argv carried it: {argv:?}"
        );
        if let Some(s) = stdin {
            changes += 1;
            let gate = s.find("\\if :sinter_quiet").unwrap();
            let at = s.find(&v).expect("the change carries the verifier");
            assert!(gate < at);
            for setting in [
                "SET log_statement = 'none';",
                "SET log_min_error_statement = 'panic';",
                "SET log_min_messages = 'panic';",
            ] {
                assert!(s.find(setting).unwrap() < gate, "{setting}");
            }
            assert_eq!(argv[argv.len() - 2..], ["-f", "-"]);
        } else {
            assert!(argv.iter().any(|a| a == "-c"), "observations use -c");
        }
    }
    assert_eq!(changes, 1, "exactly one change script");
    // Every psql ran as the cluster owner through setpriv; the fake refuses
    // anything else, and the run succeeded.
}

#[test]
fn only_declared_attributes_change_and_nothing_is_granted() {
    let f = fx("pgrole-declared");
    f.put("app.age", verifier('C').as_bytes());
    let r = f.recipe(
        "  - id: role\n    type: postgresql_role\n    with:\n      name: app\n      login: true\n",
    );
    let mut t = target(130_023);
    t.pg.roles.insert(
        "app".into(),
        FakePgRole {
            attrs: [false, false, true, false, true, false, false],
            ..Default::default()
        },
    );
    let rep = run(&r, Mode::Apply, &f, &mut t).unwrap();
    assert_eq!(res(&rep).verification, Verification::Verified);
    let role = &t.pg.roles["app"];
    assert!(role.attrs[0], "login set");
    assert!(role.attrs[2], "createdb was not declared and is untouched");
    assert!(role.password.is_none(), "no password declared, none set");
    let script = psql_calls(&t).into_iter().find_map(|(_, s)| s).unwrap();
    assert!(
        script.contains("ALTER ROLE \"app\" WITH LOGIN;\n"),
        "{script}"
    );
    assert!(!script.contains("NOCREATEDB"));
    assert!(!script.contains("PASSWORD"));
}

#[test]
fn a_changed_verifier_is_drift_and_only_the_password_is_altered() {
    let f = fx("pgrole-drift");
    let v = verifier('D');
    f.put("app.age", v.as_bytes());
    let r = f.role("      login: true\n");
    let mut t = target(160_015);
    t.pg.roles.insert(
        "app".into(),
        FakePgRole {
            attrs: [true, false, false, false, true, false, false],
            password: Some(verifier('Z')),
            ..Default::default()
        },
    );
    let a = audit(&r, &f, &t);
    assert_eq!(a.resources[0].status, AuditResourceStatus::Drift);
    assert_eq!(a.resources[0].details.len(), 1);
    assert_eq!(a.resources[0].details[0].dimension, "password_verifier");
    clean(&v, &audit_surfaces(&a));
    clean(&verifier('Z'), &audit_surfaces(&a));

    let rep = run(&r, Mode::Apply, &f, &mut t).unwrap();
    assert_eq!(res(&rep).verification, Verification::Verified);
    assert_eq!(t.pg.roles["app"].password.as_deref(), Some(v.as_str()));
    let script = psql_calls(&t).into_iter().find_map(|(_, s)| s).unwrap();
    assert_eq!(script.matches("ALTER ROLE").count(), 1);
    assert!(script.contains("ALTER ROLE \"app\" PASSWORD '"));
    clean(&v, &surfaces(&rep, "apply"));
    clean(&verifier('Z'), &surfaces(&rep, "apply"));
}

#[test]
fn an_md5_password_is_drift_against_a_declared_scram_verifier() {
    let f = fx("pgrole-md5");
    f.put("app.age", verifier('E').as_bytes());
    let r = f.role("");
    let mut t = target(100_023);
    t.pg.roles.insert(
        "app".into(),
        FakePgRole {
            password: Some("md5aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into()),
            ..Default::default()
        },
    );
    assert_eq!(
        audit(&r, &f, &t).resources[0].status,
        AuditResourceStatus::Drift
    );
}

// ---------------------------------------------------------------------------
// fail closed
// ---------------------------------------------------------------------------

/// When the session cannot be shown to keep statements out of the server
/// log, nothing carrying the verifier runs and the resource fails.
#[test]
fn unverified_log_suppression_sends_no_change() {
    let f = fx("pgrole-unquiet");
    f.put("app.age", verifier('F').as_bytes());
    let r = f.role("      login: true\n");
    let mut t = target(170_011);
    t.pg.quiet_fails = true;
    let rep = run(&r, Mode::Apply, &f, &mut t).unwrap();
    let p = res(&rep);
    assert_eq!(p.execution, Execution::Failed);
    assert_eq!(p.change, Change::None);
    assert!(p.reason.as_deref().unwrap().contains("was not sent"));
    assert!(!t.pg.roles.contains_key("app"));
}

/// A refused change (the transaction rolled back) is proven unchanged by
/// observing again; psql's output is withheld.
#[test]
fn a_refused_change_is_reported_without_psql_output() {
    let f = fx("pgrole-refused");
    let v = verifier('G');
    f.put("app.age", v.as_bytes());
    let r = f.role("      login: true\n");
    let mut t = target(170_011);
    t.pg.fail_change = true;
    let rep = run(&r, Mode::Apply, &f, &mut t).unwrap();
    let p = res(&rep);
    assert_eq!(p.execution, Execution::Failed);
    assert_eq!(
        p.change,
        Change::None,
        "observed unchanged after the refusal"
    );
    let reason = p.reason.clone().unwrap();
    assert!(reason.contains("psql exited 3"), "{reason}");
    assert!(reason.contains("output withheld"), "{reason}");
    assert!(!reason.contains("ERROR"), "{reason}");
    clean(&v, &surfaces(&rep, "apply"));
}

#[test]
fn a_secret_that_is_not_a_scram_verifier_is_refused_before_psql() {
    for bad in [
        "correct horse battery staple".to_string(),
        "md5aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        verifier('H').replace("4096", "1000"),
        format!("{}'; DROP ROLE postgres; --", verifier('H')),
    ] {
        let f = fx("pgrole-badsecret");
        f.put("app.age", bad.as_bytes());
        let r = f.role("      login: true\n");
        let mut t = target(170_011);
        let e = run(&r, Mode::Apply, &f, &mut t);
        let text = match &e {
            Err(e) => e.message.clone(),
            Ok(rep) => res(rep).reason.clone().unwrap_or_default(),
        };
        assert!(
            text.contains("not an accepted SCRAM-SHA-256 verifier"),
            "{text}"
        );
        assert!(!text.contains(&bad));
        assert!(psql_calls(&t).is_empty(), "nothing reached psql");
    }
}

#[test]
fn the_connecting_role_is_never_dropped_or_demoted() {
    let f = fx("pgrole-lockout");
    for body in [
        "  - id: role\n    type: postgresql_role\n    with:\n      name: postgres\n      state: absent\n",
        "  - id: role\n    type: postgresql_role\n    with:\n      name: postgres\n      superuser: false\n",
        "  - id: role\n    type: postgresql_role\n    with:\n      name: postgres\n      login: false\n",
    ] {
        let r = f.recipe(body);
        let mut t = target(170_011);
        let text = match run(&r, Mode::Apply, &f, &mut t) {
            Err(e) => e.message,
            Ok(rep) => res(&rep).reason.clone().unwrap_or_default(),
        };
        assert!(text.contains("refusing to change PostgreSQL role postgres"), "{text}");
        assert!(t.pg.roles.contains_key("postgres"));
        assert!(psql_calls(&t).is_empty());
    }
}

#[test]
fn absent_drops_without_cascade_and_is_idempotent() {
    let f = fx("pgrole-absent");
    let r = f.recipe(
        "  - id: role\n    type: postgresql_role\n    with:\n      name: old_app\n      state: absent\n",
    );
    let mut t = target(130_023);
    t.pg.roles.insert("old_app".into(), FakePgRole::default());
    let rep = run(&r, Mode::Apply, &f, &mut t).unwrap();
    assert_eq!(res(&rep).verification, Verification::Verified);
    assert!(!t.pg.roles.contains_key("old_app"));
    let script = psql_calls(&t).into_iter().find_map(|(_, s)| s).unwrap();
    assert!(script.contains("DROP ROLE \"old_app\";\n"));
    assert!(!script.contains("CASCADE"));
    let again = run(&r, Mode::Apply, &f, &mut t).unwrap();
    assert_eq!(res(&again).change, Change::None);
}

#[test]
fn needs_root() {
    let f = fx("pgrole-root");
    f.put("app.age", verifier('I').as_bytes());
    let r = f.role("      login: true\n");
    let t = target(170_011);
    let e = engine(&r, Mode::Apply, false, Some(f.src()), t.clone())
        .unwrap()
        .run();
    let text = match e {
        Err(e) => e.message,
        Ok(rep) => res(&rep).reason.clone().unwrap_or_default(),
    };
    assert!(text.contains("postgresql_role needs root"), "{text}");
}

#[test]
fn a_server_that_is_not_running_fails_apply_but_is_unknown_in_plan_after_a_change() {
    let f = fx("pgrole-down");
    f.put("app.age", verifier('J').as_bytes());
    // Apply alone: an observation failure is an error, never a guess.
    let r = f.role("      login: true\n");
    let mut t = target(170_011);
    t.pg.running = false;
    let text = match run(&r, Mode::Apply, &f, &mut t) {
        Err(e) => e.message,
        Ok(rep) => res(&rep).reason.clone().unwrap_or_default(),
    };
    assert!(text.contains("cannot observe PostgreSQL role"), "{text}");
    assert!(
        !text.contains("No such file"),
        "psql output is withheld: {text}"
    );

    // Plan after an earlier change (the package/service that will provide
    // the server): Unknown, not an error.
    let r = f.recipe(
        "  - id: pkg\n    type: package\n    with:\n      name: postgresql-server\n      state: present\n  - id: role\n    type: postgresql_role\n    depends_on: [pkg]\n    with:\n      name: app\n      login: true\n",
    );
    let mut t = target(170_011);
    t.pg.running = false;
    let rep = run(&r, Mode::Plan, &f, &mut t).unwrap();
    let p = res(&rep);
    assert!(p.unknown, "{:?}", p.reason);
    assert!(p
        .reason
        .as_deref()
        .unwrap()
        .contains("before earlier planned changes"));
}

// ---------------------------------------------------------------------------
// schema
// ---------------------------------------------------------------------------

#[test]
fn schema_rejects_unsafe_declarations() {
    let f = fx("pgrole-schema");
    for (body, needle) in [
        ("      name: App\n", "not a valid role name"),
        ("      name: pg_monitor\n", "not a valid role name"),
        ("      name: \"a'b\"\n", "not a valid role name"),
        ("      name: app\n      password_verifier: SCRAM-SHA-256$x\n", "password_verifier must be { secret"),
        ("      name: app\n      state: absent\n      password_verifier: { secret: secrets/app.age }\n", "cannot be combined with state: absent"),
        ("      name: app\n      superuser: yes please\n", "superuser must be a boolean"),
        ("      name: app\n      connection_limit: -5\n", "connection_limit"),
        ("      name: app\n      psql: psql\n", "psql must be /usr/bin/psql or /usr/pgsql-<major>/bin/psql"),
        // plan/audit run psql: a recipe or manifest cannot pick the binary
        ("      name: app\n      psql: /tmp/x/psql\n", "psql must be /usr/bin/psql or /usr/pgsql-<major>/bin/psql"),
        ("      name: app\n      port: 0\n", "port must be"),
        ("      name: app\n      database: \"x;y\"\n", "database must be"),
        ("      name: app\n      password: hunter2\n", "unknown field with.password"),
    ] {
        f.put("app.age", verifier('K').as_bytes());
        let r = f.recipe(&format!(
            "  - id: role\n    type: postgresql_role\n    with:\n{body}"
        ));
        let e = load_model(&r).unwrap_err();
        assert!(e.message.contains(needle), "{body}: {}", e.message);
        assert!(!e.message.contains("hunter2"));
    }
}

#[test]
fn one_resource_per_role_also_across_an_omitted_default_port() {
    let f = fx("pgrole-conflict-port");
    let r = f.recipe(
        "  - id: a\n    type: postgresql_role\n    with:\n      name: app\n  - id: b\n    type: postgresql_role\n    with:\n      name: app\n      port: 5432\n",
    );
    let e = load_model(&r).unwrap_err();
    assert!(e.message.contains("conflicting ownership"), "{}", e.message);
    // A different port is a different server.
    let r = f.recipe(
        "  - id: a\n    type: postgresql_role\n    with:\n      name: app\n  - id: b\n    type: postgresql_role\n    with:\n      name: app\n      port: 5433\n",
    );
    load_model(&r).expect("two servers");
}

#[test]
fn one_resource_per_role() {
    let f = fx("pgrole-conflict");
    let r = f.recipe(
        "  - id: a\n    type: postgresql_role\n    with:\n      name: app\n  - id: b\n    type: postgresql_role\n    with:\n      name: app\n      login: true\n",
    );
    let e = load_model(&r).unwrap_err();
    assert!(
        e.message
            .contains("conflicting ownership of PostgreSQL role app"),
        "{}",
        e.message
    );
}
