//! `examples/openstack/files/ensure.sh`, the imperative helper of the OpenStack demo recipes, run
//! against stand-in commands (`openstack`, `mariadb`, `ovs-vsctl`, ... are small scripts that keep their state
//! in files). This proves the helper's contract, not that OpenStack works:
//!   * the LAST stdout line is exactly `changed` or `unchanged`, which the recipes' `changed_when` reads;
//!   * a second run over the state the first run left reports `unchanged` and changes nothing (idempotence);
//!   * failures exit non-zero with a message and never print a secret.
//!
//! Real behaviour of the real tools is verified only on a Rocky Linux host (see the GCE readiness report).
#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const SCRIPT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/examples/openstack/files/ensure.sh"
);

const SECRETS_ENV: &str = "KEYSTONE_DB_PASS=kdbSECRET1\nGLANCE_DB_PASS=gdbSECRET2\nPLACEMENT_DB_PASS=pdbSECRET3\n\
NEUTRON_DB_PASS=ndbSECRET4\nNOVA_DB_PASS=vdbSECRET5\nRABBIT_PASS=rabbitSECRET6\nADMIN_PASSWORD=adminSECRET7\n\
GLANCE_SERVICE_PASS=gsvcSECRET8\nPLACEMENT_SERVICE_PASS=psvcSECRET9\nNEUTRON_SERVICE_PASS=nsvcSECRET10\n\
NOVA_SERVICE_PASS=vsvcSECRET11\n";

const ALL_SECRETS: [&str; 11] = [
    "kdbSECRET1",
    "gdbSECRET2",
    "pdbSECRET3",
    "ndbSECRET4",
    "vdbSECRET5",
    "rabbitSECRET6",
    "adminSECRET7",
    "gsvcSECRET8",
    "psvcSECRET9",
    "nsvcSECRET10",
    "vsvcSECRET11",
];

/// Stand-in commands. Each is a bash script; `$S` is the state directory (set by the test environment).
const STUBS: &[(&str, &str)] = &[
    (
        "mariadb",
        r#"
echo "mariadb $*" >> "$S/calls.log"
sql=""; while [ $# -gt 0 ]; do [ "$1" = -e ] && { sql="$2"; shift; }; shift; done
[ -n "$sql" ] || sql="$(cat)"   # SQL on stdin (passwords stay off the command line)
mkdir -p "$S/db"; touch "$S/db/dbs" "$S/db/users"
case "$sql" in
  "SELECT 1") echo 1 ;;
  USE*) n="$(echo "$sql" | sed 's/USE `\(.*\)`/\1/')"; grep -qx "$n" "$S/db/dbs" ;;
  "CREATE DATABASE"*) n="$(echo "$sql" | sed 's/CREATE DATABASE `\([^`]*\)`.*/\1/')"; echo "$n" >> "$S/db/dbs" ;;
  "SELECT COUNT(*) FROM mysql.user"*)
     u="$(echo "$sql" | sed "s/.*User='\([^']*\)'.*/\1/")"; h="$(echo "$sql" | sed "s/.*Host='\([^']*\)'.*/\1/")"
     grep -cx "$u@$h" "$S/db/users" || true ;;
  "CREATE USER"*) u="$(echo "$sql" | sed "s/CREATE USER '\([^']*\)'@'\([^']*\)'.*/\1@\2/")"; echo "$u" >> "$S/db/users" ;;
  "SELECT COUNT(*) FROM information_schema.tables"*)
     d="$(echo "$sql" | sed "s/.*table_schema='\([^']*\)'.*/\1/")"; cat "$S/db/tables_$d" 2>/dev/null || echo 0 ;;
  GRANT*|FLUSH*) : ;;
  *) echo "mariadb stub: unhandled SQL: $sql" >&2; exit 9 ;;
esac
"#,
    ),
    (
        "runuser",
        r#"
echo "runuser $*" >> "$S/calls.log"
[ "$1" = -u ] || exit 9
shift 2; [ "$1" = -- ] && shift
exec "$@"
"#,
    ),
    (
        "keystone-manage",
        r#"
echo "keystone-manage $1" >> "$S/calls.log"
case "$1" in
  db_sync) mkdir -p "$S/db"; [ -f "$S/db/tables_keystone" ] || echo 40 > "$S/db/tables_keystone" ;;
  fernet_setup) mkdir -p "$S/keys/fernet"; echo k > "$S/keys/fernet/0" ;;
  credential_setup) mkdir -p "$S/keys/cred"; echo k > "$S/keys/cred/0" ;;
  bootstrap) touch "$S/bootstrapped" ;;
esac
"#,
    ),
    (
        "nova-manage",
        r#"
echo "nova-manage $*" >> "$S/calls.log"
case "$*" in
  "cell_v2 discover_hosts --verbose")
     [ -f "$S/nm-fail" ] && { echo "Traceback: could not connect mysql+pymysql://nova:vdbSECRET5@127.0.0.1/nova_api" >&2; exit 1; }
     echo "Found 2 cell mappings."; echo "Skipping cell0 since it does not contain hosts."
     if [ -f "$S/unmapped" ]; then echo "Found 1 unmapped computes in cell: abc"; rm -f "$S/unmapped"
     else echo "Found 0 unmapped computes in cell: abc"; fi ;;
esac
"#,
    ),
    (
        "glance-manage",
        r#"
echo "glance-manage $*" >> "$S/calls.log"
if [ -f "$S/gm-fail" ]; then echo "oslo.db error with password gdbSECRET2 on connection" >&2; exit 3; fi
mkdir -p "$S/db"; echo 20 > "$S/db/tables_glance"
"#,
    ),
    (
        "ovn-sbctl",
        r#"
echo "ovn-sbctl $*" >> "$S/calls.log"
args=(); for a in "$@"; do case "$a" in --timeout=*) ;; *) args+=("$a") ;; esac; done
case "${args[0]}" in
  get-connection) [ -f "$S/ovs/sb-conn" ] && echo "read-write role=\"\" $(cat "$S/ovs/sb-conn")"; true ;;
  set-connection) mkdir -p "$S/ovs"; echo "${args[1]}" > "$S/ovs/sb-conn" ;;
esac
"#,
    ),
    (
        "ovn-nbctl",
        r#"
echo "ovn-nbctl $*" >> "$S/calls.log"
args=(); for a in "$@"; do case "$a" in --timeout=*) ;; *) args+=("$a") ;; esac; done
case "${args[0]}" in
  get-connection) [ -f "$S/ovs/nb-conn" ] && cat "$S/ovs/nb-conn"; true ;;
  set-connection) mkdir -p "$S/ovs"; echo "${args[1]}" > "$S/ovs/nb-conn" ;;
esac
"#,
    ),
    (
        "getenforce",
        r#"cat "$S/selinux" 2>/dev/null || echo Enforcing"#,
    ),
    (
        "setenforce",
        r#"echo "setenforce $*" >> "$S/calls.log"; [ "$1" = 0 ] && echo Permissive > "$S/selinux""#,
    ),
    ("chown", r#"echo "chown $*" >> "$S/calls.log""#),
    (
        "systemctl",
        r#"
echo "systemctl $*" >> "$S/calls.log"
case "$1" in
  is-enabled) [ -f "$S/enabled-$2" ] ;;
  is-active) [ "$2" = --quiet ] && [ -f "$S/enabled-$3" ] ;;
  disable) rm -f "$S/enabled-$3" ;;
esac
"#,
    ),
    (
        "rabbitmqctl",
        r#"
echo "rabbitmqctl $1" >> "$S/calls.log"
case "$1" in
  list_users) printf 'Listing users ...\nuser\ttags\n'; [ -f "$S/rabbit-user" ] && printf 'openstack\t[]\n'; : ;;
  add_user) touch "$S/rabbit-user" ;;
  list_permissions) printf 'Listing permissions ...\n'; [ -f "$S/rabbit-perm" ] && printf 'openstack\t.*\t.*\t.*\n'; : ;;
  set_permissions) touch "$S/rabbit-perm" ;;
esac
"#,
    ),
    (
        "ovs-vsctl",
        r#"
echo "ovs-vsctl $*" >> "$S/calls.log"
args=(); for a in "$@"; do case "$a" in --timeout=*|--if-exists|--may-exist) ;; *) args+=("$a") ;; esac; done
mkdir -p "$S/ovs"
case "${args[0]}" in
  get) k="${args[3]#external-ids:}"; if [ -f "$S/ovs/ext-$k" ]; then echo "\"$(cat "$S/ovs/ext-$k")\""; fi ;;
  set) kv="${args[3]#external-ids:}"; echo "${kv#*=}" > "$S/ovs/ext-${kv%%=*}" ;;
  br-exists) [ -f "$S/ovs/br-${args[1]}" ] ;;
  add-br) touch "$S/ovs/br-${args[1]}" ;;
  get-manager) cat "$S/ovs/manager" 2>/dev/null ;;
  set-manager) echo "${args[1]}" > "$S/ovs/manager" ;;
esac
"#,
    ),
    (
        "openstack",
        r#"
echo "openstack $*" >> "$S/calls.log"
mkdir -p "$S/os"
noun="$1"
case "$*" in
  "token issue"*) [ -f "$S/bootstrapped" ] && echo tokenid; exit $? ;;
  "project show admin"*) echo adminproj; exit 0 ;;
  "security group list"*) echo "sg1 default"; exit 0 ;;
  "security group rule create"*)
      key="$(echo "$*" | tr -c 'a-z0-9' _)"
      if [ -f "$S/os/rule-$key" ]; then echo "Conflict (HTTP 409): rule already exists" >&2; exit 1; fi
      touch "$S/os/rule-$key"; exit 0 ;;
  "role assignment list"*) key="$(echo "$*" | tr -c 'a-z0-9' _)"; [ -f "$S/os/assign" ] && echo assigned; exit 0 ;;
  "role add"*) touch "$S/os/assign"; exit 0 ;;
  "endpoint list"*) cat "$S/os/endpoint-$(echo "$*" | sed 's/.*--service \([^ ]*\) .*/\1/')-$(echo "$*" | sed 's/.*--interface \([^ ]*\) .*/\1/')" 2>/dev/null; exit 0 ;;
  "endpoint create"*) shift  # now: create --region R service iface url
      echo "ep-$4-$5 $6" > "$S/os/endpoint-$4-$5"; exit 0 ;;
  "endpoint set"*) shift  # now: set --url U ID
      for f in "$S"/os/endpoint-*; do [ "$(cut -d' ' -f1 "$f")" = "$4" ] && echo "$4 $3" > "$f"; done; exit 0 ;;
  "image show"*"-c status"*) n="$3"; [ -f "$S/os/image-$n" ] || exit 1; cat "$S/os/image-$n.state" 2>/dev/null || echo active; exit 0 ;;
  "image delete"*) rm -f "$S/os/image-$3" "$S/os/image-$3.state"; exit 0 ;;
esac
shift
verb="$1"; shift
case "$verb" in
  show) name=""; for a in "$@"; do case "$a" in -*) break ;; *) name="$a"; break ;; esac; done
        [ -f "$S/os/$noun-$name" ] ;;
  create)
        name=""; prev=""
        for a in "$@"; do [ "$prev" = --name ] && name="$a"; prev="$a"; done
        [ -n "$name" ] || for a in "$@"; do name="$a"; done
        # the keypair's private key is the command's output
        if [ "$noun" = keypair ]; then echo "-----BEGIN SYNTHETIC TEST KEY-----"; fi
        touch "$S/os/$noun-$name" ;;
  *) : ;;
esac
"#,
    ),
];

struct Env {
    dir: tempfile::TempDir,
}

impl Env {
    fn new() -> Env {
        let dir = tempfile::tempdir().unwrap();
        let s = dir.path();
        let bin = s.join("bin");
        fs::create_dir_all(&bin).unwrap();
        for (name, body) in STUBS {
            let p = bin.join(name);
            fs::write(&p, format!("#!/bin/bash\n{body}")).unwrap();
            make_exec(&p);
        }
        let etc = s.join("etc");
        fs::create_dir_all(&etc).unwrap();
        fs::write(etc.join("secrets.env"), SECRETS_ENV).unwrap();
        fs::write(
            etc.join("admin-openrc"),
            "export OS_AUTH_URL=http://127.0.0.1:5000/v3\nexport OS_USERNAME=admin\nexport OS_PASSWORD=adminSECRET7\n",
        )
        .unwrap();
        Env { dir }
    }

    fn s(&self) -> &Path {
        self.dir.path()
    }

    /// Run the helper. Returns (exit code, stdout, stderr).
    fn run(&self, args: &[&str]) -> (i32, String, String) {
        let s = self.s();
        let path = format!("{}:/usr/bin:/bin", s.join("bin").display());
        let out = Command::new("/bin/bash")
            .arg(SCRIPT)
            .args(args)
            .env_clear()
            .env("PATH", path)
            .env("S", s)
            .env("SINTER_OS_ETC", s.join("etc"))
            .env("SINTER_OS_STATE", s.join("state"))
            .env("SINTER_OS_HORIZON_SETTINGS", s.join("local_settings"))
            .env("SINTER_OS_REPO_DIR", s.join("repos"))
            .output()
            .unwrap();
        let o = String::from_utf8_lossy(&out.stdout).into_owned();
        let e = String::from_utf8_lossy(&out.stderr).into_owned();
        for sec in ALL_SECRETS {
            assert!(
                !o.contains(sec),
                "{args:?} printed a secret on stdout:\n{o}"
            );
            assert!(
                !e.contains(sec),
                "{args:?} printed a secret on stderr:\n{e}"
            );
        }
        (out.status.code().unwrap_or(-1), o, e)
    }

    /// Run and require exit 0 and a verdict as the last stdout line.
    fn verdict(&self, args: &[&str]) -> String {
        let (code, o, e) = self.run(args);
        assert_eq!(code, 0, "{args:?} failed\nstdout: {o}\nstderr: {e}");
        let last = o.lines().last().unwrap_or("").to_string();
        assert!(
            last == "changed" || last == "unchanged",
            "{args:?}: last stdout line is {last:?}"
        );
        last
    }

    /// First run changes, second run reports unchanged.
    fn converges(&self, args: &[&str]) {
        assert_eq!(self.verdict(args), "changed", "{args:?} first run");
        assert_eq!(self.verdict(args), "unchanged", "{args:?} second run");
    }

    fn calls(&self) -> String {
        fs::read_to_string(self.s().join("calls.log")).unwrap_or_default()
    }
}

fn make_exec(p: &PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(p, fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn unknown_subcommand_and_missing_argument_fail_cleanly() {
    let e = Env::new();
    let (code, o, err) = e.run(&["no-such-step"]);
    assert_ne!(code, 0);
    assert!(o.is_empty(), "stdout must be empty on failure: {o}");
    assert!(err.contains("unknown subcommand"), "{err}");
    let (code, _, err) = e.run(&[]);
    assert_ne!(code, 0);
    assert!(err.contains("usage"), "{err}");
}

#[test]
fn selinux_permissive_changes_once() {
    let e = Env::new();
    e.converges(&["selinux-permissive"]);
    assert_eq!(e.calls().matches("setenforce 0").count(), 1);
}

#[test]
fn selinux_disabled_is_reported_not_changed() {
    let e = Env::new();
    fs::write(e.s().join("selinux"), "Disabled\n").unwrap();
    assert_eq!(e.verdict(&["selinux-permissive"]), "unchanged");
    assert!(!e.calls().contains("setenforce"), "{}", e.calls());
}

#[test]
fn databases_users_and_grants_converge() {
    let e = Env::new();
    for db in [
        "keystone",
        "glance",
        "placement",
        "neutron",
        "nova_api",
        "nova",
        "nova_cell0",
    ] {
        e.converges(&["db", db]);
    }
    // the account passwords go to the client on stdin, never on its command line
    assert!(
        !e.calls().contains("IDENTIFIED BY"),
        "a password reached a command line:\n{}",
        e.calls()
    );
    let users = fs::read_to_string(e.s().join("db/users")).unwrap();
    // nova_api, nova and nova_cell0 share one account (the user is `nova`), per host once
    assert_eq!(
        users.lines().filter(|l| *l == "nova@localhost").count(),
        1,
        "{users}"
    );
    assert_eq!(
        users.lines().filter(|l| *l == "nova@%").count(),
        1,
        "{users}"
    );
    assert!(users.lines().any(|l| l == "keystone@%"));
    let (code, _, err) = e.run(&["db", "bogus"]);
    assert_ne!(code, 0);
    assert!(err.contains("unknown database"), "{err}");
}

#[test]
fn schema_sync_reports_changed_only_when_tables_appear() {
    let e = Env::new();
    e.converges(&["sync", "keystone"]);
}

#[test]
fn nova_discover_hosts_reports_changed_only_when_a_compute_was_mapped() {
    let e = Env::new();
    // "Found N cell mappings." is printed on every run and must NOT count as a change
    assert_eq!(e.verdict(&["nova-cell", "discover"]), "unchanged");
    fs::write(e.s().join("unmapped"), "").unwrap();
    assert_eq!(e.verdict(&["nova-cell", "discover"]), "changed");
    assert_eq!(e.verdict(&["nova-cell", "discover"]), "unchanged");
    // a failing discovery is an error, not a silent "unchanged", and its output is masked
    fs::write(e.s().join("nm-fail"), "").unwrap();
    let (code, o, err) = e.run(&["nova-cell", "discover"]);
    assert_ne!(code, 0);
    assert!(o.is_empty(), "{o}");
    assert!(err.contains("discover_hosts failed"), "{err}");
}

#[test]
fn a_failing_schema_sync_shows_masked_output_and_fails() {
    let e = Env::new();
    fs::write(e.s().join("gm-fail"), "").unwrap();
    let (code, o, err) = e.run(&["sync", "glance"]);
    assert_ne!(code, 0);
    assert!(o.is_empty(), "{o}");
    assert!(err.contains("glance-manage db_sync failed"), "{err}");
    // the tool's own output is shown (that is the point) with the password masked (the harness also
    // asserts that no secret appears on stdout or stderr)
    assert!(err.contains("oslo.db error with password ***"), "{err}");
    fs::remove_file(e.s().join("gm-fail")).unwrap();
    e.converges(&["sync", "glance"]);
}

#[test]
fn keystone_keys_and_bootstrap_converge() {
    let e = Env::new();
    // the fernet/credential key steps test fixed /etc/keystone paths and cannot run here; they are covered on a
    // real host. Bootstrap's verdict depends on whether the admin can already authenticate.
    e.converges(&["keystone-bootstrap", "10.0.0.10", "RegionOne"]);
    assert!(e.calls().contains("keystone-manage bootstrap"));
    assert_eq!(e.calls().matches("keystone-manage bootstrap").count(), 1);
}

#[test]
fn keystone_key_setup_keeps_stdout_for_the_verdict() {
    // The key steps write fixed /etc/keystone paths and cannot run here (they ran on a real host). What is
    // pinned: keystone-manage's own output (oslo.log writes to stdout by default) goes through run_logged, so
    // stdout stays exactly "changed"/"unchanged" for changed_when; on a failure the output goes to stderr.
    let src = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/openstack/files/ensure.sh"),
    )
    .unwrap();
    for step in ["fernet_setup", "credential_setup"] {
        let calls: Vec<&str> = src
            .lines()
            .filter(|l| l.contains(&format!("keystone-manage {step} --keystone-user")))
            .collect();
        assert_eq!(calls.len(), 1, "{step}");
        let i = src.find(calls[0]).unwrap();
        let before = &src[..i];
        let prev = before.trim_end().lines().last().unwrap_or("");
        assert!(
            prev.contains(&format!("run_logged \"keystone-manage {step}\"")),
            "{step} must run through run_logged: {prev}"
        );
    }
}

#[test]
fn keystone_objects_are_created_once() {
    let e = Env::new();
    e.converges(&["ks-project", "service"]);
    for u in ["glance", "placement", "neutron", "nova"] {
        e.converges(&["ks-user", u]);
    }
    let (code, _, err) = e.run(&["ks-user", "mallory"]);
    assert_ne!(code, 0);
    assert!(err.contains("unknown service user"), "{err}");
    e.converges(&["ks-role", "glance", "service", "admin"]);
    e.converges(&["ks-service", "glance", "image", "OpenStack Image"]);
    e.converges(&[
        "ks-endpoint",
        "glance",
        "public",
        "http://10.0.0.10:9292",
        "RegionOne",
    ]);
    // an endpoint that exists with a different URL is converged to the wanted one (changed once, then unchanged)
    let (code, o, err) = e.run(&[
        "ks-endpoint",
        "glance",
        "public",
        "http://other:9292",
        "RegionOne",
    ]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(o.trim(), "changed");
    assert!(
        e.calls().contains("endpoint set --url http://other:9292"),
        "{}",
        e.calls()
    );
    assert_eq!(
        e.verdict(&[
            "ks-endpoint",
            "glance",
            "public",
            "http://other:9292",
            "RegionOne"
        ]),
        "unchanged"
    );
}

#[test]
fn initial_resources_converge() {
    let e = Env::new();
    fs::write(e.s().join("bootstrapped"), "").unwrap();
    e.converges(&["os-flavor", "m1.tiny", "1", "512", "1"]);
    e.converges(&["os-keypair", "demo-key"]);
    let key = fs::read_to_string(e.s().join("etc/demo-key")).unwrap();
    assert!(key.starts_with("-----BEGIN"), "{key}");
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(e.s().join("etc/demo-key"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "private key must be 0600");
    e.converges(&[
        "os-net-provider",
        "provider",
        "physnet1",
        "provider-sub",
        "203.0.113.0/24",
        "203.0.113.1",
        "203.0.113.100",
        "203.0.113.200",
    ]);
    e.converges(&[
        "os-net-tenant",
        "tenant",
        "tenant-sub",
        "192.168.100.0/24",
        "8.8.8.8",
    ]);
    e.converges(&["os-secgroup-rule", "ssh"]);
    e.converges(&["os-secgroup-rule", "icmp"]);
    let (code, _, err) = e.run(&["os-secgroup-rule", "telnet"]);
    assert_ne!(code, 0);
    assert!(err.contains("unknown rule"), "{err}");
}

#[test]
fn image_digest_mismatch_is_refused_before_upload() {
    let e = Env::new();
    // a file already in place with the wrong digest, and no way to download: the helper must not upload it
    let imgs = e.s().join("state/images");
    fs::create_dir_all(&imgs).unwrap();
    fs::write(imgs.join("cirros.img"), "not the image").unwrap();
    // the stand-in `curl` writes other bytes, so the digest cannot match
    fs::write(
        e.s().join("bin/curl"),
        "#!/bin/bash\nwhile [ $# -gt 0 ]; do [ \"$1\" = -o ] && echo other > \"$2\"; shift; done\n",
    )
    .unwrap();
    make_exec(&e.s().join("bin/curl"));
    fs::write(
        e.s().join("bin/sha256sum"),
        "#!/bin/bash\nprintf '%s  %s\\n' deadbeef \"$1\"\n",
    )
    .unwrap();
    make_exec(&e.s().join("bin/sha256sum"));
    let (code, _, err) = e.run(&["os-image", "cirros", "http://x/cirros.img", "00ff"]);
    assert_ne!(code, 0);
    assert!(err.contains("digest mismatch"), "{err}");
    assert!(
        !e.calls().contains("image create"),
        "the image was uploaded despite the mismatch:\n{}",
        e.calls()
    );
}

#[test]
fn rabbit_user_converges_and_keeps_the_password_off_the_output() {
    let e = Env::new();
    e.converges(&["rabbit-user"]);
    assert_eq!(e.calls().matches("rabbitmqctl add_user").count(), 1);
}

#[test]
fn ovs_settings_converge() {
    let e = Env::new();
    e.converges(&["ovs-set", "ovn-remote", "tcp:10.0.0.10:6642"]);
    // a changed value is changed again, an unchanged one is left
    assert_eq!(
        e.verdict(&["ovs-set", "ovn-remote", "tcp:10.0.0.11:6642"]),
        "changed"
    );
    e.converges(&["ovs-bridge", "br-int"]);
    e.converges(&["ovs-manager", "ptcp:6640:127.0.0.1"]);
    // OVN connections: SB's get-connection line carries `read-write role=""` before the target (found on a real
    // host); NB prints the bare target. Both must converge.
    e.converges(&["ovn-connection", "sb", "ptcp:6642:10.0.0.10"]);
    e.converges(&["ovn-connection", "nb", "ptcp:6641:127.0.0.1"]);
    assert_eq!(
        e.verdict(&["ovn-connection", "sb", "ptcp:6642:10.0.0.11"]),
        "changed"
    );
}

#[test]
fn horizon_block_is_replaced_not_appended() {
    let e = Env::new();
    let settings = e.s().join("local_settings");
    fs::write(&settings, "DEBUG = False\nALLOWED_HOSTS = ['*']\n").unwrap();
    let block = e.s().join("block");
    fs::write(&block, "# >>> sinter-openstack begin — managed block, edit above this line\nWEBROOT = '/'\n# <<< sinter-openstack end\n").unwrap();
    e.converges(&["horizon-settings", block.to_str().unwrap()]);
    let first = fs::read_to_string(&settings).unwrap();
    assert!(
        first.starts_with("DEBUG = False\nALLOWED_HOSTS = ['*']\n"),
        "{first}"
    );
    assert_eq!(first.matches("sinter-openstack begin").count(), 1);
    // a new block replaces the old one; the distribution part above is kept byte for byte
    fs::write(&block, "# >>> sinter-openstack begin — managed block, edit above this line\nWEBROOT = '/dashboard/'\n# <<< sinter-openstack end\n").unwrap();
    assert_eq!(
        e.verdict(&["horizon-settings", block.to_str().unwrap()]),
        "changed"
    );
    let second = fs::read_to_string(&settings).unwrap();
    assert!(second.starts_with("DEBUG = False\nALLOWED_HOSTS = ['*']\n"));
    assert_eq!(
        second.matches("sinter-openstack begin").count(),
        1,
        "{second}"
    );
    assert!(
        second.contains("/dashboard/") && !second.contains("WEBROOT = '/'\n"),
        "{second}"
    );
    assert_eq!(
        e.verdict(&["horizon-settings", block.to_str().unwrap()]),
        "unchanged"
    );
    // a missing settings file is an error, not a created file
    fs::remove_file(&settings).unwrap();
    let (code, _, err) = e.run(&["horizon-settings", block.to_str().unwrap()]);
    assert_ne!(code, 0);
    assert!(err.contains("does not exist"), "{err}");
    assert!(!settings.exists());
}

#[test]
fn a_missing_secrets_file_is_an_error_that_names_the_file() {
    let e = Env::new();
    fs::remove_file(e.s().join("etc/secrets.env")).unwrap();
    let (code, o, err) = e.run(&["db", "keystone"]);
    assert_ne!(code, 0);
    assert!(o.is_empty());
    assert!(err.contains("secrets.env is not readable"), "{err}");
}

#[test]
fn an_image_that_never_finished_uploading_is_replaced_and_an_active_one_is_left() {
    let e = Env::new();
    fs::write(e.s().join("bootstrapped"), "").unwrap();
    // an upload that died leaves the image `queued`: it must be deleted and uploaded again
    fs::create_dir_all(e.s().join("os")).unwrap();
    fs::write(e.s().join("os/image-cirros"), "").unwrap();
    fs::write(e.s().join("os/image-cirros.state"), "queued\n").unwrap();
    fs::create_dir_all(e.s().join("state/images")).unwrap();
    fs::write(e.s().join("state/images/cirros.img"), "bytes").unwrap();
    fs::write(
        e.s().join("bin/sha256sum"),
        "#!/bin/bash\nprintf '%s  %s\\n' 00ff \"$1\"\n",
    )
    .unwrap();
    make_exec(&e.s().join("bin/sha256sum"));
    assert_eq!(
        e.verdict(&["os-image", "cirros", "http://x/cirros.img", "00ff"]),
        "changed"
    );
    assert!(e.calls().contains("image delete cirros"), "{}", e.calls());
    assert!(e.calls().contains("image create"), "{}", e.calls());
    // the new image is active: nothing more to do
    let _ = fs::remove_file(e.s().join("os/image-cirros.state"));
    assert_eq!(
        e.verdict(&["os-image", "cirros", "http://x/cirros.img", "00ff"]),
        "unchanged"
    );
    // an image still being saved is not touched: the run stops and says so
    fs::write(e.s().join("os/image-cirros.state"), "saving\n").unwrap();
    let (code, _, err) = e.run(&["os-image", "cirros", "http://x/cirros.img", "00ff"]);
    assert_ne!(code, 0);
    assert!(err.contains("not active"), "{err}");
}

#[test]
fn a_network_without_its_subnet_gets_the_subnet() {
    let e = Env::new();
    fs::write(e.s().join("bootstrapped"), "").unwrap();
    fs::create_dir_all(e.s().join("os")).unwrap();
    // a run that died between the two creates
    fs::write(e.s().join("os/network-tenant"), "").unwrap();
    assert_eq!(
        e.verdict(&[
            "os-net-tenant",
            "tenant",
            "tenant-sub",
            "192.168.100.0/24",
            "8.8.8.8"
        ]),
        "changed"
    );
    assert!(e.calls().contains("subnet create"), "{}", e.calls());
    assert_eq!(
        e.verdict(&[
            "os-net-tenant",
            "tenant",
            "tenant-sub",
            "192.168.100.0/24",
            "8.8.8.8"
        ]),
        "unchanged"
    );
    fs::write(e.s().join("os/network-provider"), "").unwrap();
    assert_eq!(
        e.verdict(&[
            "os-net-provider",
            "provider",
            "physnet1",
            "provider-sub",
            "203.0.113.0/24",
            "203.0.113.1",
            "203.0.113.100",
            "203.0.113.200"
        ]),
        "changed"
    );
    assert_eq!(
        e.verdict(&[
            "os-net-provider",
            "provider",
            "physnet1",
            "provider-sub",
            "203.0.113.0/24",
            "203.0.113.1",
            "203.0.113.100",
            "203.0.113.200"
        ]),
        "unchanged"
    );
}
