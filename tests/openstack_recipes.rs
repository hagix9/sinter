//! The OpenStack 2026.1 (Gazpacho) demo recipes for Rocky Linux 10.2 (`examples/openstack`), a port
//! of hagistack's `rocky10.2/hagistack`.
//!
//! What this proves, locally and on a scripted target ([`FakeTarget`], Rocky 10): the recipes are valid, the
//! dependency graph is acyclic and orders what must be ordered (package → config → service, database → schema
//! → registration → API), the all-in-one recipe is exactly the controller plus the compute role without any
//! resource managed twice, the compute-only role opens no database, plan renders the intended files, and no
//! secret reaches an output. What it cannot prove: that OpenStack works. Commands, packages and services are
//! scripted here; only a real Rocky Linux host can show that (a real-host acceptance run is needed).
mod common;

use common::*;
use sinter::engine::{AggregateStatus, Mode, RunReport};
use sinter::executor::FakeTarget;
use sinter::model::{load_model, Model};
use sinter::result::{Change, DiffBody};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const ENTRIES: [&str; 3] = ["all-in-one", "controller", "compute"];

/// Distinct dummy secrets: a leak of any of them in an output is found by name.
const SECRET_KEYS: [&str; 14] = [
    "mysql_root_pass",
    "keystone_db_pass",
    "glance_db_pass",
    "placement_db_pass",
    "neutron_db_pass",
    "nova_db_pass",
    "rabbit_pass",
    "admin_password",
    "glance_service_pass",
    "placement_service_pass",
    "neutron_service_pass",
    "nova_service_pass",
    "metadata_proxy_secret",
    "horizon_secret_key",
];
const COMPUTE_KEYS: [&str; 5] = [
    "rabbit_pass",
    "nova_service_pass",
    "placement_service_pass",
    "neutron_service_pass",
    "metadata_proxy_secret",
];

fn source_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/openstack")
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for e in fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let (src, dst) = (e.path(), to.join(e.file_name()));
        if e.file_type().unwrap().is_dir() {
            if e.file_name() == "secrets" {
                continue;
            }
            copy_tree(&src, &dst);
        } else {
            fs::copy(&src, &dst).unwrap();
        }
    }
}

fn secret_value(key: &str) -> String {
    format!("DUMMYSECRET{}X", key.replace('_', "").to_uppercase())
}

/// A private copy of the recipe tree with generated dummy secrets (never the real tool's output).
fn workdir(label: &str, strip_sensitive: bool) -> PathBuf {
    workdir_with(label, strip_sensitive, false)
}

/// `drop_deps` additionally removes every `depends_on`: a plan then renders the files that command
/// dependencies would otherwise leave Unknown (render tests only; ordering is tested on the real graph).
fn workdir_with(label: &str, strip_sensitive: bool, drop_deps: bool) -> PathBuf {
    let dir = trusted_root(label);
    copy_tree(&source_dir(), &dir);
    let sec = dir.join("secrets");
    fs::create_dir_all(&sec).unwrap();
    let write = |name: &str, keys: &[&str]| {
        let mut s = String::from("version: 1\nvars:\n");
        for k in SECRET_KEYS {
            let v = if keys.contains(&k) {
                secret_value(k)
            } else {
                String::new()
            };
            s.push_str(&format!(
                "  {k}:\n    value: \"{v}\"\n    sensitive: {}\n",
                !strip_sensitive
            ));
        }
        fs::write(sec.join(name), s).unwrap();
    };
    write("controller.yaml", &SECRET_KEYS);
    write("compute.yaml", &COMPUTE_KEYS);
    if strip_sensitive || drop_deps {
        // Only to read rendered files in a plan diff: the sensitive flag hides them on purpose.
        fn strip(d: &Path, sens: bool, deps: bool) {
            for e in fs::read_dir(d).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    strip(&p, sens, deps);
                } else if p.extension().map(|x| x == "yaml").unwrap_or(false) {
                    fs::write(&p, rewrite(&fs::read_to_string(&p).unwrap(), sens, deps)).unwrap();
                }
            }
        }
        strip(&dir.join("components"), strip_sensitive, drop_deps);
        for e in ENTRIES {
            let p = dir.join(format!("{e}.yaml"));
            let t = fs::read_to_string(&p).unwrap();
            fs::write(&p, rewrite(&t, strip_sensitive, drop_deps)).unwrap();
        }
    }
    dir
}

fn rewrite(text: &str, sens: bool, deps: bool) -> String {
    text.lines()
        .filter(|l| !(sens && l.trim() == "sensitive: true" && l.starts_with("    ")))
        .filter(|l| !(deps && l.trim_start().starts_with("depends_on: [") && l.starts_with("    ")))
        .map(|l| format!("{l}\n"))
        .collect()
}

fn model(dir: &Path, entry: &str) -> Model {
    load_model(&dir.join(format!("{entry}.yaml")))
        .unwrap_or_else(|e| panic!("{entry}: {}", e.message))
}

/// The execution order: dependencies first, ties by declaration order (the rule `sinter` documents; computed
/// here independently so that a change in the engine's ordering shows up as a failed expectation).
fn execution_order_for_tests(m: &Model) -> Vec<usize> {
    let index: BTreeMap<&str, usize> = m
        .resources
        .iter()
        .enumerate()
        .map(|(i, r)| (r.id.as_str(), i))
        .collect();
    let n = m.resources.len();
    let mut indeg = vec![0usize; n];
    let mut dependents: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (i, r) in m.resources.iter().enumerate() {
        for d in r.depends_on.iter().collect::<BTreeSet<_>>() {
            let di = index[d.as_str()];
            indeg[i] += 1;
            dependents[di].push(i);
        }
    }
    let mut ready: BTreeSet<usize> = (0..n).filter(|i| indeg[*i] == 0).collect();
    let mut order = Vec::new();
    while let Some(&i) = ready.iter().next() {
        ready.remove(&i);
        order.push(i);
        for &d in &dependents[i] {
            indeg[d] -= 1;
            if indeg[d] == 0 {
                ready.insert(d);
            }
        }
    }
    assert_eq!(order.len(), n, "the dependency graph has a cycle");
    order
}

fn ids(m: &Model) -> BTreeSet<String> {
    m.resources.iter().map(|r| r.id.clone()).collect()
}

/// `a` runs strictly before `b` in the execution order.
fn before(m: &Model, order: &[usize], a: &str, b: &str) -> bool {
    let pos = |id: &str| {
        let i = m
            .resources
            .iter()
            .position(|r| r.id == id)
            .unwrap_or_else(|| panic!("no resource {id}"));
        order.iter().position(|x| *x == i).unwrap()
    };
    pos(a) < pos(b)
}

/// Is `dep` among the (transitive) dependencies of `id`?
fn depends(m: &Model, id: &str, dep: &str) -> bool {
    let by: BTreeMap<&str, &Vec<String>> = m
        .resources
        .iter()
        .map(|r| (r.id.as_str(), &r.depends_on))
        .collect();
    let mut stack = vec![id];
    let mut seen = BTreeSet::new();
    while let Some(c) = stack.pop() {
        for d in by.get(c).map(|v| v.as_slice()).unwrap_or(&[]) {
            if d == dep {
                return true;
            }
            if seen.insert(d.as_str()) {
                stack.push(d.as_str());
            }
        }
    }
    false
}

#[test]
fn every_entry_point_is_a_valid_recipe_of_the_expected_size() {
    let dir = workdir("os-valid", false);
    let sizes: Vec<(usize, usize)> = ENTRIES
        .iter()
        .map(|e| {
            let m = model(&dir, e);
            (m.resources.len(), m.handlers.len())
        })
        .collect();
    // all-in-one > controller > compute; compute-only is small: no database, no identity, no API.
    assert!(
        sizes[0].0 > sizes[1].0 && sizes[1].0 > sizes[2].0,
        "{sizes:?}"
    );
    assert!(sizes[2].0 < 60, "{sizes:?}");
}

#[test]
fn all_in_one_is_the_controller_plus_the_compute_role_and_nothing_twice() {
    let dir = workdir("os-aio-union", false);
    let (aio, ctrl, comp) = (
        ids(&model(&dir, "all-in-one")),
        ids(&model(&dir, "controller")),
        ids(&model(&dir, "compute")),
    );
    // The compute role's only controller-side ingredient is the reachability check; everything else of the
    // compute role is in the all-in-one recipe, and nothing of the controller role is missing from it.
    let mut union: BTreeSet<String> = ctrl.union(&comp).cloned().collect();
    union.remove("compute_reach_controller");
    let extras: BTreeSet<String> = ["wait_compute_up", "nova_discover_hosts"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let expected: BTreeSet<String> = union.union(&extras).cloned().collect();
    assert_eq!(
        aio,
        expected,
        "only in all-in-one: {:?}; only expected: {:?}",
        aio.difference(&expected).collect::<Vec<_>>(),
        expected.difference(&aio).collect::<Vec<_>>()
    );
    // A compute-only node has no controller service.
    for id in [
        "svc_httpd",
        "svc_mariadb",
        "keystone_bootstrap",
        "svc_ovn_northd",
        "os_image",
        "svc_nova_conductor",
    ] {
        assert!(!comp.contains(id), "{id} must not be in the compute role");
        assert!(ctrl.contains(id) && aio.contains(id), "{id}");
    }
    // The compute role's own pieces are in all-in-one and not in the controller-only role.
    for id in ["svc_nova_compute", "svc_libvirtd", "pkg_qemu_kvm"] {
        assert!(
            comp.contains(id) && aio.contains(id) && !ctrl.contains(id),
            "{id}"
        );
    }
}

#[test]
fn every_managed_path_is_managed_once() {
    // Sinter rejects two resources on the same exact path at load time; this keeps the expectation visible and
    // checks the paths that the roles share (nova.conf, the metadata agent, the repositories).
    let dir = workdir("os-paths", false);
    for e in ENTRIES {
        let m = model(&dir, e);
        let mut seen = BTreeMap::new();
        for r in &m.resources {
            if let Some(sinter::value::Value::Str(p)) = r.with.get("path") {
                if r.with.contains_key("state") && r.type_ == "service" {
                    continue;
                }
                assert!(
                    seen.insert(p.clone(), r.id.clone()).is_none(),
                    "{e}: {p} is managed twice"
                );
            }
        }
    }
}

#[test]
fn the_dependency_graph_orders_what_must_be_ordered() {
    let dir = workdir("os-order", false);
    for e in ["all-in-one", "controller"] {
        let m = model(&dir, e);
        // `depends`, not `before`: execution order alone also holds by declaration-order ties, which is not a
        // guarantee. The edge must be in the graph (directly or through other resources).
        let b = |a: &str, c: &str| {
            assert!(
                depends(&m, c, a),
                "{e}: {c} must (transitively) depend on {a}"
            )
        };
        // repositories → packages → configuration → services
        b("repo_gazpacho_answers", "pkg_keystone");
        b("pkg_mariadb", "mariadb_conf");
        b("mariadb_conf", "svc_mariadb");
        b("svc_mariadb", "db_keystone");
        // identity: schema, keys, front end, bootstrap, then every registration
        b("db_keystone", "keystone_db_sync");
        // the key setup needs no database; the schema must exist before httpd serves Keystone
        b("keystone_conf", "keystone_fernet");
        b("keystone_db_sync", "svc_httpd");
        b("keystone_fernet", "svc_httpd");
        b("vhost_nova_api", "svc_httpd");
        b("svc_httpd", "wait_keystone");
        b("wait_keystone", "keystone_bootstrap");
        b("keystone_bootstrap", "ks_project_service");
        for svc in ["glance", "placement", "neutron", "nova"] {
            b("ks_project_service", &format!("ks_user_{svc}"));
            b(&format!("ks_user_{svc}"), &format!("ks_role_{svc}"));
            b(
                &format!("ks_service_{svc}"),
                &format!("ks_endpoint_{svc}_public"),
            );
            assert!(
                depends(
                    &m,
                    &format!("ks_endpoint_{svc}_admin"),
                    &format!("ks_service_{svc}")
                ),
                "{e}"
            );
        }
        // each service starts after its configuration, its schema and its registration
        b("glance_conf", "svc_glance_api");
        b("glance_db_sync", "svc_glance_api");
        b("ks_endpoint_glance_admin", "svc_glance_api");
        b("neutron_conf", "neutron_db_sync");
        b("wait_ovn", "neutron_db_sync");
        b("neutron_plugin_ini", "svc_neutron_rpc_server");
        b("nova_conf", "nova_db_sync");
        b("nova_db_sync", "nova_cell1");
        b("nova_cell1", "svc_nova_conductor");
        // the initial resources need the APIs they use
        b("wait_nova_api_auth", "os_flavor_tiny");
        b("wait_glance_api", "os_image");
        b("wait_neutron_api", "os_net_tenant");
        b("os_net_provider", "os_router");
        // OVN: central connections before the chassis agent, the loopback manager before the metadata agent
        b("ovn_sb_connection", "svc_ovn_controller");
        b("ovs_manager", "svc_neutron_ovn_metadata_agent");
        b("svc_ovn_controller", "svc_neutron_ovn_metadata_agent");
        // dashboard: settings, assets, then the login page is probed
        b("horizon_settings", "horizon_assets");
        b("horizon_assets", "wait_horizon");
    }
    // The all-in-one recipe adds the hypervisor, registers it and maps it into a cell.
    let m = model(&dir, "all-in-one");
    for (a, c) in [
        ("nova_conf", "svc_nova_compute"),
        ("svc_libvirtd", "svc_nova_compute"),
        ("svc_nova_compute", "wait_compute_up"),
        ("wait_compute_up", "nova_discover_hosts"),
    ] {
        assert!(depends(&m, c, a), "all-in-one: {c} must depend on {a}");
    }
    // The hypervisor starts only after what it talks to is up (found by the independent review: this used to
    // hold only through declaration order).
    for dep in [
        "rabbit_user",
        "svc_nova_conductor",
        "wait_placement_api",
        "wait_neutron_api",
        "svc_ovn_controller",
    ] {
        assert!(
            depends(&m, "svc_nova_compute", dep),
            "svc_nova_compute must depend on {dep}"
        );
    }
}

#[test]
fn a_service_never_runs_before_the_package_that_ships_its_unit() {
    let dir = workdir("os-pkg-svc", false);
    let expect = [
        ("svc_mariadb", "pkg_mariadb"),
        ("svc_rabbitmq", "pkg_rabbitmq"),
        ("svc_memcached", "pkg_memcached"),
        ("svc_httpd", "pkg_httpd"),
        ("svc_glance_api", "pkg_glance"),
        ("svc_openvswitch", "pkg_openvswitch"),
        ("svc_ovn_northd", "pkg_ovn_central"),
        ("svc_ovn_controller", "pkg_ovn_host"),
        ("svc_neutron_rpc_server", "pkg_neutron_rpc_server"),
        (
            "svc_neutron_periodic_workers",
            "pkg_neutron_periodic_workers",
        ),
        (
            "svc_neutron_ovn_maintenance_worker",
            "pkg_neutron_ovn_maintenance_worker",
        ),
        ("svc_neutron_ovn_metadata_agent", "pkg_ovn_metadata_agent"),
        ("svc_nova_conductor", "pkg_nova_conductor"),
        ("svc_nova_scheduler", "pkg_nova_scheduler"),
        ("svc_nova_compute", "pkg_nova_compute"),
        ("svc_libvirtd", "pkg_libvirt"),
    ];
    for e in ["all-in-one", "controller", "compute"] {
        let m = model(&dir, e);
        let have = ids(&m);
        for (svc, pkg) in expect {
            if have.contains(svc) {
                assert!(depends(&m, svc, pkg), "{e}: {svc} must depend on {pkg}");
            }
        }
        // every service resource depends on some package (it needs a unit file)
        // (the loopback repository server is shipped by Sinter itself: its unit file is a managed resource)
        for r in m
            .resources
            .iter()
            .filter(|r| r.type_ == "service" && r.id != "svc_repo_local")
        {
            let pkgs: Vec<&str> = m
                .resources
                .iter()
                .filter(|p| p.type_ == "package")
                .map(|p| p.id.as_str())
                .collect();
            assert!(
                pkgs.iter().any(|p| depends(&m, &r.id, p)),
                "{e}: service {} depends on no package",
                r.id
            );
        }
    }
}

#[test]
fn a_config_file_is_written_after_the_package_that_creates_its_group() {
    // keystone/glance/placement/neutron/nova/apache accounts come from the RPMs (no `user` resource): the file
    // must name the package. Plan cannot know those accounts before the install (see the dependency report).
    let dir = workdir("os-owner-dep", false);
    let m = model(&dir, "all-in-one");
    for (file, pkg) in [
        ("keystone_conf", "pkg_keystone"),
        ("glance_conf", "pkg_glance"),
        ("placement_conf", "pkg_placement"),
        ("neutron_conf", "pkg_neutron"),
        ("ml2_conf", "pkg_neutron_ml2"),
        ("ovn_metadata_ini", "pkg_ovn_metadata_agent"),
        ("nova_conf", "pkg_nova_api"),
        ("nova_conf", "pkg_nova_compute"),
        ("glance_images_dir", "pkg_glance"),
        ("nova_tmp_dir", "pkg_nova_compute"),
        ("dashboard_static_dir", "pkg_dashboard"),
    ] {
        assert!(depends(&m, file, pkg), "{file} must depend on {pkg}");
    }
}

#[test]
fn a_changed_configuration_restarts_exactly_the_services_that_read_it() {
    let dir = workdir("os-notify", false);
    let notified = |m: &Model, id: &str| -> BTreeSet<String> {
        m.resources
            .iter()
            .find(|r| r.id == id)
            .unwrap()
            .notify
            .iter()
            .cloned()
            .collect()
    };
    let set = |v: &[&str]| -> BTreeSet<String> { v.iter().map(|s| s.to_string()).collect() };
    let aio = model(&dir, "all-in-one");
    assert_eq!(
        notified(&aio, "nova_conf"),
        set(&[
            "restart_nova_conductor",
            "restart_nova_scheduler",
            "restart_nova_compute",
            "reload_httpd"
        ])
    );
    assert_eq!(notified(&aio, "glance_conf"), set(&["restart_glance_api"]));
    assert_eq!(notified(&aio, "mariadb_conf"), set(&["restart_mariadb"]));
    assert_eq!(
        notified(&aio, "ovn_metadata_ini"),
        set(&["restart_neutron_ovn_metadata_agent"])
    );
    assert!(notified(&aio, "vhost_nova_api").contains("reload_httpd"));
    assert!(notified(&aio, "keystone_conf").contains("reload_httpd"));
    // a compute-only node restarts only nova-compute (it has no conductor or scheduler unit)
    let comp = model(&dir, "compute");
    assert_eq!(notified(&comp, "nova_conf"), set(&["restart_nova_compute"]));
    // every handler names a unit that some resource of the recipe makes sure is running
    for e in ENTRIES {
        let m = model(&dir, e);
        let units: BTreeSet<String> = m
            .resources
            .iter()
            .filter(|r| r.type_ == "service")
            .filter_map(|r| match r.with.get("name") {
                Some(sinter::value::Value::Str(s)) => Some(s.clone()),
                _ => None,
            })
            .collect();
        for h in &m.handlers {
            assert!(
                units.contains(&h.service),
                "{e}: handler {} names {} which no service resource manages",
                h.id,
                h.service
            );
        }
    }
}

fn rocky() -> FakeTarget {
    let mut t = FakeTarget::rocky10().with_fake_fs().as_root();
    for d in [
        "/etc/yum.repos.d",
        "/etc/httpd",
        "/etc/httpd/conf.d",
        "/etc/my.cnf.d",
        "/etc/sysconfig",
        "/etc/selinux",
        "/etc/systemd",
        "/etc/systemd/system",
        "/usr",
        "/usr/lib",
        "/usr/local",
        "/usr/local/libexec",
        "/usr/share",
        "/usr/share/openstack-dashboard",
        "/var",
        "/var/lib",
        "/var/lib/glance",
        "/var/lib/nova",
        "/etc/neutron",
        "/etc/neutron/plugins",
        "/etc/neutron/plugins/ml2",
        "/etc/nova",
        "/etc/glance",
        "/etc/placement",
        "/etc/keystone",
        "/etc/openvswitch",
        "/opt",
    ] {
        t = t.with_fs_dir(d);
    }
    t
}

/// The accounts the RPMs create, as they exist AFTER the install.
fn rocky_with_package_accounts() -> FakeTarget {
    let mut t = rocky();
    for (i, n) in [
        "keystone",
        "glance",
        "placement",
        "neutron",
        "nova",
        "apache",
        "openvswitch",
        "hugetlbfs",
    ]
    .iter()
    .enumerate()
    {
        let id = 300 + i as u32;
        t = t
            .with_group(n, id)
            .with_user(n, id, id, &format!("/var/lib/{n}"), "/sbin/nologin");
    }
    // ... and so do the units the RPMs install (loaded, inactive, disabled, as a fresh install leaves them).
    for u in [
        "mariadb",
        "rabbitmq-server",
        "memcached",
        "httpd",
        "openstack-glance-api",
        "openvswitch",
        "ovn-northd",
        "ovn-controller",
        "neutron-rpc-server",
        "neutron-periodic-workers",
        "neutron-ovn-maintenance-worker",
        "neutron-ovn-metadata-agent",
        "openstack-nova-conductor",
        "openstack-nova-scheduler",
        "openstack-nova-compute",
        "virtqemud.socket",
        "sinter-openstack-repo.service",
    ] {
        t = t.with_service(u, ("loaded", "inactive", "disabled"));
    }
    t
}

/// The host with a placeholder at every path whose rendering a test reads: a plan shows the text of a change
/// only where there is an old text to compare with.
fn rocky_with_placeholders() -> FakeTarget {
    let mut t = rocky_with_package_accounts();
    for p in [
        "/etc/nova/nova.conf",
        "/etc/neutron/neutron_ovn_metadata_agent.ini",
        "/etc/neutron/plugins/ml2/ml2_conf.ini",
        "/etc/neutron/neutron.conf",
        "/etc/my.cnf.d/99-sinter-openstack.cnf",
        "/etc/sysconfig/memcached",
        "/etc/httpd/conf.d/10-sinter-openstack-nova-api.conf",
        "/etc/httpd/conf.d/10-sinter-openstack-keystone.conf",
        "/etc/httpd/conf.d/10-sinter-openstack-neutron.conf",
        "/etc/yum.repos.d/sinter-openstack-gazpacho.repo",
        "/etc/sinter-openstack/horizon-block.py",
        "/etc/sinter-openstack/secrets.env",
    ] {
        if let Some(dir) = p.rsplit_once('/').map(|x| x.0) {
            t = t.with_fs_dir(dir);
        }
        t = t.with_fs_file(p, "placeholder\n");
    }
    t
}

fn assert_plan_ok(r: &RunReport) {
    assert!(
        matches!(
            r.status,
            AggregateStatus::Success | AggregateStatus::Indeterminate
        ),
        "plan status {:?}: {:?}",
        r.status,
        r.resources
            .iter()
            .filter(|x| x.reason.is_some() && !x.unknown)
            .map(|x| (&x.id, &x.reason))
            .collect::<Vec<_>>()
    );
}

#[test]
fn plan_of_every_entry_completes_on_a_host_whose_package_accounts_exist() {
    let dir = workdir("os-plan", false);
    for e in ENTRIES {
        let r = run_recipe_fake(
            &dir.join(format!("{e}.yaml")),
            Mode::Plan,
            true,
            rocky_with_package_accounts(),
        );
        assert_plan_ok(&r);
        assert_eq!(mutation_command_count(&r), 0, "{e}: plan mutates nothing");
        // commands are never executed in plan: they and what depends on them are unknown, not changed
        assert!(find(&r, "preflight_os").unknown, "{e}");
        assert!(find(&r, "helper").change == Change::Changed, "{e}");
    }
}

#[test]
fn plan_on_a_fresh_host_defers_what_depends_on_a_command_and_does_not_guess_package_accounts() {
    // The accounts that the keystone/glance/... packages create cannot be predicted by plan (F-3 covers `user`
    // and `group` resources only). On a fresh host plan still completes, because every file that names such an
    // account depends (through the repository check) on a command, and plan never runs commands: those files
    // are Unknown ("?"), not errors and not guesses. Without the command in the chain, plan would stop with an
    // unknown-account error (see the dependency verification report).
    let dir = workdir("os-plan-fresh", false);
    let r = run_recipe_fake(&dir.join("all-in-one.yaml"), Mode::Plan, true, rocky());
    assert_plan_ok(&r);
    for id in [
        "keystone_conf",
        "glance_conf",
        "nova_conf",
        "neutron_conf",
        "svc_nova_compute",
    ] {
        assert!(
            find(&r, id).unknown,
            "{id} must be deferred on a fresh host"
        );
    }
    let unknown = r.resources.iter().filter(|x| x.unknown).count();
    eprintln!(
        "fresh-host plan: {unknown} of {} resources Unknown",
        r.resources.len()
    );
    assert!(
        unknown * 10 > r.resources.len() * 8,
        "most of the plan is Unknown ({unknown} of {})",
        r.resources.len()
    );
}

#[test]
fn rendered_configuration_matches_the_hagistack_settings() {
    let dir = workdir_with("os-render", true, true);
    let aio = run_recipe_fake(
        &dir.join("all-in-one.yaml"),
        Mode::Plan,
        true,
        rocky_with_placeholders(),
    );
    let comp = run_recipe_fake(
        &dir.join("compute.yaml"),
        Mode::Plan,
        true,
        rocky_with_placeholders(),
    );
    let text = |r: &RunReport, id: &str| -> String {
        match &find(r, id)
            .diff
            .as_ref()
            .unwrap_or_else(|| panic!("no diff for {id}"))
            .body
        {
            DiffBody::Text { added, .. } => added.join("\n"),
            other => panic!("{id}: {other:?}"),
        }
    };
    // nova.conf: the cell database is opened on the all-in-one node and only there
    let n_aio = text(&aio, "nova_conf");
    let n_comp = text(&comp, "nova_conf");
    assert!(
        n_aio.contains("\nconnection = mysql+pymysql://nova:"),
        "{n_aio}"
    );
    assert!(n_aio.contains("[api_database]\nconnection = mysql+pymysql://nova:"));
    assert!(
        !n_comp.contains("\nconnection = mysql+pymysql"),
        "a compute node must not open a database"
    );
    assert!(n_comp.contains("# connection = mysql+pymysql://nova:"));
    for t in [&n_aio, &n_comp] {
        assert!(t.contains("compute_driver = libvirt.LibvirtDriver"));
        assert!(t.contains("state_path = /var/lib/nova"));
        assert!(t.contains("host = osdemo1"));
        assert!(t.contains("virt_type = kvm"));
        assert!(t.contains("[os_vif_ovs]\novsdb_connection = tcp:127.0.0.1:6640"));
        assert!(t.contains("server_listen = 10.0.0.10"));
    }
    // the OVN metadata agent: the two root-helper keys are in [AGENT], the OVS manager is loopback
    let md = text(&aio, "ovn_metadata_ini");
    assert!(md.contains("[AGENT]\nroot_helper = sudo neutron-rootwrap /etc/neutron/rootwrap.conf\nroot_helper_daemon = sudo neutron-rootwrap-daemon /etc/neutron/rootwrap.conf"));
    assert!(md.contains("[ovs]\novsdb_connection = tcp:127.0.0.1:6640"));
    assert!(!md.contains("[DEFAULT]\nroot_helper"));
    // ML2/OVN
    let ml2 = text(&aio, "ml2_conf");
    assert!(
        ml2.contains("mechanism_drivers = ovn") && ml2.contains("tenant_network_types = geneve")
    );
    assert!(
        ml2.contains("ovn_nb_connection = tcp:127.0.0.1:6641")
            && ml2.contains("ovn_sb_connection = tcp:10.0.0.10:6642")
    );
    let neu = text(&aio, "neutron_conf");
    assert!(neu.contains("service_plugins = ovn-router") && neu.contains("[nova]"));
    // the loopback-only database
    assert!(text(&aio, "mariadb_conf").contains("bind-address = 127.0.0.1"));
    assert!(text(&aio, "memcached_conf").contains("OPTIONS=\"-l 10.0.0.10,127.0.0.1\""));
    // vhosts: the four mod_wsgi front ends
    let v = text(&aio, "vhost_nova_api");
    assert!(
        v.contains("Listen 8774")
            && v.contains(
                "WSGIScriptAlias / /usr/lib/python3.12/site-packages/nova/wsgi/osapi_compute.py"
            )
    );
    assert!(
        v.contains("user=nova group=nova")
            && v.contains("<Directory /usr/lib/python3.12/site-packages/nova/wsgi>")
    );
    assert!(text(&aio, "vhost_keystone").contains("Listen 5000"));
    assert!(text(&aio, "vhost_neutron").contains("neutron/wsgi/api.py"));
    // the repository file points at the pinned RPM repository
    assert!(
        text(&aio, "repo_gazpacho").contains("baseurl=file:///opt/hagistack-repo")
            || text(&aio, "repo_gazpacho").contains("priority=1")
    );
    // the Horizon block starts with the marker that the helper looks for
    let hz = text(&aio, "horizon_block");
    assert!(hz.starts_with("# >>> sinter-openstack begin"), "{hz}");
    // the compute node's secrets file has only the five delivered credentials filled
    let sec = text(&comp, "secrets_env");
    assert!(sec.contains(&format!("RABBIT_PASS={}", secret_value("rabbit_pass"))));
    assert!(
        sec.contains("KEYSTONE_DB_PASS=\n") || sec.contains("KEYSTONE_DB_PASS="),
        "{sec}"
    );
    assert!(
        !sec.contains(&secret_value("keystone_db_pass"))
            && !sec.contains(&secret_value("admin_password"))
    );
}

#[test]
fn no_secret_reaches_any_output_of_plan_or_apply() {
    use sinter::output::{render_apply, render_plan, OutputFormat, RenderOptions};
    let dir = workdir("os-leak", false);
    let all_secrets: Vec<String> = SECRET_KEYS.iter().map(|k| secret_value(k)).collect();
    for e in ENTRIES {
        let plan = run_recipe_fake(
            &dir.join(format!("{e}.yaml")),
            Mode::Plan,
            true,
            rocky_with_package_accounts(),
        );
        let apply = run_recipe_fake(
            &dir.join(format!("{e}.yaml")),
            Mode::Apply,
            true,
            rocky_with_package_accounts(),
        );
        for (what, rep, is_plan) in [("plan", &plan, true), ("apply", &apply, false)] {
            for format in [OutputFormat::Text, OutputFormat::Json] {
                let mut buf = Vec::new();
                let opts = RenderOptions {
                    verbose: true,
                    format,
                    color: false,
                };
                if is_plan {
                    render_plan(rep, &opts, &mut buf).unwrap();
                } else {
                    render_apply(rep, &opts, &mut buf).unwrap();
                }
                let out = String::from_utf8(buf).unwrap();
                for s in &all_secrets {
                    assert!(
                        !out.contains(s.as_str()),
                        "{e}/{what}: a secret appears in the output"
                    );
                }
            }
            let log = format!("{:?}", rep.commands);
            for s in &all_secrets {
                assert!(
                    !log.contains(s.as_str()),
                    "{e}/{what}: a secret appears in the command log"
                );
            }
        }
    }
}

#[test]
fn the_helper_script_is_installed_root_only_and_the_secrets_files_are_private() {
    let dir = workdir("os-modes", false);
    let m = model(&dir, "all-in-one");
    let mode = |id: &str| match m
        .resources
        .iter()
        .find(|r| r.id == id)
        .unwrap()
        .with
        .get("mode")
    {
        Some(sinter::value::Value::Str(s)) => s.clone(),
        o => panic!("{id}: {o:?}"),
    };
    assert_eq!(mode("helper"), "0750");
    assert_eq!(mode("secrets_env"), "0600");
    assert_eq!(mode("admin_openrc"), "0600");
    assert_eq!(mode("etc_dir"), "0700");
    for id in [
        "keystone_conf",
        "glance_conf",
        "placement_conf",
        "neutron_conf",
        "ml2_conf",
        "nova_conf",
        "ovn_metadata_ini",
    ] {
        assert_eq!(mode(id), "0640", "{id}");
    }
    // every resource that carries a secret is sensitive (templates with the secret vars)
    for r in m.resources.iter().filter(|r| {
        [
            "keystone_conf",
            "glance_conf",
            "placement_conf",
            "neutron_conf",
            "nova_conf",
            "secrets_env",
            "admin_openrc",
            "horizon_block",
        ]
        .contains(&r.id.as_str())
    }) {
        assert!(
            r.sensitive || r.derived_sensitive,
            "{} must be sensitive",
            r.id
        );
    }
}

#[test]
fn the_builder_recipe_is_valid_ordered_and_pins_the_hagistack_commit() {
    let dir = workdir("os-builder", false);
    let m = model(&dir, "builder");
    let order = execution_order_for_tests(&m);
    // the build runs after the pinned checkout, the repositories and every build tool
    for dep in [
        "src_pin",
        "builder_script",
        "crb",
        "repo_rdo_delorean",
        "repo_rdo_deps",
        "pkg_rpm_build",
        "pkg_createrepo_c",
        "pkg_python3",
    ] {
        assert!(
            depends(&m, "build_rpms", dep),
            "build_rpms must depend on {dep}"
        );
        assert!(before(&m, &order, dep, "build_rpms"));
    }
    assert!(depends(&m, "src_pin", "src_clone"));
    // the repository fix-up (drop the incomplete self-built cliff) runs after the build
    assert!(depends(&m, "repo_fixup", "build_rpms"));
    // the RDO repository files hagistack's recorded builds used are installed before the build
    assert!(
        depends(&m, "build_rpms", "repo_rdo_deps")
            && depends(&m, "build_rpms", "repo_rdo_delorean")
    );
    // the source is pinned to a commit id, not a branch
    let text = fs::read_to_string(dir.join("builder.yaml")).unwrap();
    assert!(
        text.contains("8225c50c0b283bcdce960d64f7f7dfe32f5afc1c"),
        "the hagistack commit must be pinned"
    );
    // plan: nothing is executed; the build and its checkout are Unknown on a fresh host
    let r = run_recipe_fake(&dir.join("builder.yaml"), Mode::Plan, true, rocky());
    assert_plan_ok(&r);
    assert_eq!(mutation_command_count(&r), 0);
    assert!(find(&r, "build_rpms").unknown);
}

#[test]
fn services_that_use_rabbitmq_the_dashboard_and_the_metadata_agent_have_their_prerequisites_in_the_graph(
) {
    let dir = workdir("os-review-fixes", false);
    for e in ["all-in-one", "controller"] {
        let m = model(&dir, e);
        // the dashboard's own httpd vhost is on disk before httpd first starts (otherwise the login page 404s
        // until a reload that only happens at the end of a successful apply)
        assert!(depends(&m, "svc_httpd", "pkg_dashboard"), "{e}");
        for svc in [
            "svc_nova_conductor",
            "svc_nova_scheduler",
            "svc_neutron_rpc_server",
            "svc_neutron_periodic_workers",
            "svc_neutron_ovn_maintenance_worker",
        ] {
            assert!(
                depends(&m, svc, "rabbit_user"),
                "{e}: {svc} needs the rabbit user"
            );
        }
        // neutron.conf is read by the metadata agent: ordered before it, and a change restarts it
        assert!(
            depends(&m, "svc_neutron_ovn_metadata_agent", "neutron_conf"),
            "{e}"
        );
        let notified: BTreeSet<_> = m
            .resources
            .iter()
            .find(|r| r.id == "neutron_conf")
            .unwrap()
            .notify
            .iter()
            .cloned()
            .collect();
        assert!(
            notified.contains("restart_neutron_ovn_metadata_agent"),
            "{e}"
        );
        // the controller address check runs before the first package install
        let order = execution_order_for_tests(&m);
        assert!(
            before(
                &m,
                &order,
                "preflight_controller_address",
                "pkg_epel_release"
            ),
            "{e}"
        );
    }
    // the first package install waits for the OS check; no recipe fetches dnf metadata itself (Sinter >= 1.5.0
    // does it before an install whose repositories have no cached metadata)
    for e in ENTRIES.iter().copied().chain(["builder"]) {
        let m = model(&dir, e);
        assert!(depends(&m, "pkg_epel_release", "preflight_os"), "{e}");
        assert_no_makecache_command(&m, e);
    }
    // a controller-only node needs no /dev/kvm; a node with a hypervisor does
    let kvm_when = |e: &str| {
        let m = model(&dir, e);
        let r = m
            .resources
            .iter()
            .find(|r| r.id == "preflight_kvm")
            .unwrap();
        r.when.clone()
    };
    for e in ["all-in-one", "compute"] {
        assert!(
            format!("{:?}", kvm_when(e)).contains("has_hypervisor"),
            "{e}"
        );
    }
    // the compute node waits for the controller's ports before it installs anything
    let m = model(&dir, "compute");
    assert!(depends(&m, "svc_nova_compute", "compute_reach_controller"));
}

#[test]
fn findings_of_the_real_host_run_are_pinned_in_the_recipes() {
    let dir = workdir("os-real-findings", false);
    for e in ENTRIES {
        let m = model(&dir, e);
        // the chassis name survives a reboot: ovs-ctl rewrites system-id from this file at every start
        assert!(depends(&m, "svc_openvswitch", "ovs_system_id_file"), "{e}");
        let f = m
            .resources
            .iter()
            .find(|r| r.id == "ovs_system_id_file")
            .unwrap();
        assert!(
            matches!(f.with.get("owner"), Some(sinter::value::Value::Str(o)) if o == "openvswitch"),
            "{e}"
        );
        // libvirt is the modular QEMU daemon's socket (the legacy libvirtd conflicts with it and idles out)
        let l = m.resources.iter().find(|r| r.id == "svc_libvirtd");
        if let Some(l) = l {
            assert!(
                matches!(l.with.get("name"), Some(sinter::value::Value::Str(n)) if n == "virtqemud.socket"),
                "{e}"
            );
        }
        assert_no_makecache_command(&m, e);
    }
    // builder: every package other than epel/plugins-core waits for every repository it may need (CRB and the
    // RDO repo files), which in turn wait for epel-release
    let b = model(&dir, "builder");
    for p in ["pkg_git", "pkg_rpm_build", "pkg_createrepo_c", "pkg_curl"] {
        for repo in ["crb", "repo_rdo_delorean", "repo_rdo_deps"] {
            assert!(depends(&b, p, repo), "{p} -> {repo}");
        }
    }
    for repo in ["repo_rdo_delorean", "repo_rdo_deps", "crb"] {
        assert!(depends(&b, repo, "pkg_epel_release"), "{repo}");
    }
    assert_no_makecache_command(&b, "builder");
}

/// The recipes rely on Sinter's own metadata refresh (v1.5.0): no `dnf makecache` command anywhere.
fn assert_no_makecache_command(m: &Model, e: &str) {
    for r in &m.resources {
        if r.type_ == "command" {
            let text = format!("{:?}", r.with);
            assert!(
                !text.contains("makecache"),
                "{e}: {} still runs dnf makecache",
                r.id
            );
        }
    }
}

#[test]
fn audit_findings_of_phase_2_are_pinned_in_the_recipes() {
    let dir = workdir("os-p2-audit", false);
    for e in ["all-in-one", "controller"] {
        let m = model(&dir, e);
        let ids = ids(&m);
        // dead units are not "disabled" by commands any more, and nothing depends on them
        assert!(
            !ids.contains("neutron_server_unit_off") && !ids.contains("nova_api_units_off"),
            "{e}"
        );
        // the key files make their commands known to plan on a host that has them
        for k in ["keystone_fernet", "keystone_credential"] {
            let r = m.resources.iter().find(|r| r.id == k).unwrap();
            assert!(
                r.with.contains_key("creates"),
                "{e}: {k} needs a creates guard"
            );
        }
        // the dashboard assets rebuild reloads httpd inside the helper; the handler is not notified a second time
        let a = m
            .resources
            .iter()
            .find(|r| r.id == "horizon_assets")
            .unwrap();
        assert!(a.notify.is_empty(), "{e}");
        // a systemd drop-in needs a restart, not a reload
        let w = m
            .resources
            .iter()
            .find(|r| r.id == "httpd_dashboard_writepath")
            .unwrap();
        assert_eq!(w.notify, vec!["restart_httpd".to_string()], "{e}");
        assert!(depends(&m, "svc_httpd", "keystone_db_sync"), "{e}");
    }
    // the Python site-packages path lives in one variable
    let web = fs::read_to_string(dir.join("components/web.yaml")).unwrap();
    assert!(
        !web.contains("python3.12"),
        "python3.12 is hard-coded in web.yaml"
    );
    let site = fs::read_to_string(dir.join("site.yaml")).unwrap();
    assert!(site.contains("py_site_packages"));
}

#[test]
fn the_rpm_repository_is_served_over_http_before_any_package_needs_it() {
    let dir = workdir("os-repo-local", false);
    for e in ENTRIES {
        let m = model(&dir, e);
        // package installs go through the repository check, which waits for the local repository server
        assert!(
            depends(&m, "repo_gazpacho_answers", "svc_repo_local"),
            "{e}"
        );
        assert!(depends(&m, "repo_gazpacho_answers", "repo_gazpacho"), "{e}");
    }
    let site = fs::read_to_string(dir.join("site.yaml")).unwrap();
    assert!(
        site.contains("http://127.0.0.1"),
        "the default repo_url must be HTTP"
    );
    assert!(
        !site.contains("value: \"file://"),
        "file:// repositories are unusable with the package resource"
    );
}
