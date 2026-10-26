//! Scripted package database for the exact-target removal commands.
//!
//! `FakeTarget` keeps the set of installed package names; this module adds the
//! parts `dpkg` and `rpm` need to answer for them: versions and architectures,
//! which installed package requires which, essential and protected packages,
//! package-script failures, a concurrent installer and forced answers.
//!
//! The model follows the real tools where it matters for safety: the removing
//! command refuses when an installed package requires the target, and `rpm -e`
//! (unlike `dpkg --remove`) does not look at dependencies again after its
//! dry-run, so a dependent installed in between breaks and is only visible to
//! the dependency verification afterwards.

use crate::executor::{Completion, Output};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// What a package's removal script does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FakeScriptlet {
    #[default]
    Ok,
    /// The pre-removal script fails: the package stays installed.
    PreRemoveFails,
    /// The post-removal script fails and the tool exits non-zero.
    PostRemoveFails,
    /// The post-removal script fails but the tool still exits 0 and warns.
    PostRemoveWarns,
    /// The package is removed, then the tool exits non-zero for a reason that
    /// is not a script (a defective tool).
    FailsAfterRemoval,
    /// Another process removed the package first: the tool says it is not
    /// installed.
    RemovedByOther,
    /// As `RemovedByOther`, but another process had removed the package
    /// without purging, so dpkg says that only its configuration files are on
    /// the system (rpm: as `RemovedByOther`).
    RemovedByOtherConfigFiles,
    /// As `RemovedByOther`, but dpkg prints the package as `NAME:ARCH`.
    RemovedByOtherQualified,
    /// Both of the above together.
    RemovedByOtherQualifiedConfigFiles,
    /// A normal, successful removal whose maintainer script writes a message
    /// containing the words "isn't installed" to stderr.
    NoisyScript,
    /// A normal, successful removal whose maintainer script forges dpkg's own
    /// "ignoring request to remove NAME which isn't installed" warning on
    /// stderr (rpm: a scriptlet that prints the same line).
    ForgedWarning,
    /// dpkg starts the removal and the package is gone, then the tool exits
    /// non-zero; a script's output repeats dpkg's own refusal lines (a
    /// dependency problem for this package, a lock held by another process).
    /// APT only.
    FailsAfterRemovalRepeatingRefusals,
    /// Another process removed the package after the dry-run; dpkg then
    /// refused (a dependency problem it saw before the other process
    /// finished) without removing anything itself. APT only.
    RefusedThenRemovedByOther,
    /// The package is gone and dpkg failed without saying why or that it had
    /// started: nothing shows who removed the package. APT only.
    GoneThenUnexplainedFailure,
}

/// Per-package details; unset fields take the platform default.
#[derive(Debug, Clone, Default)]
pub struct FakePkg {
    pub version: Option<String>,
    pub release: Option<String>,
    pub arch: Option<String>,
    pub epoch: Option<u32>,
    pub status: Option<String>,
    /// Further installed instances of the same name as `(arch, version)`.
    pub duplicates: Vec<(String, String)>,
    /// Other architectures' instances of the same name as `(arch, status)`
    /// (dpkg status such as `deinstall ok config-files`); APT only. They are
    /// not installed names of the set `installed`.
    pub other_instances: Vec<(String, String)>,
}

#[derive(Debug, Clone, Default)]
pub struct FakePkgDb {
    pub meta: BTreeMap<String, FakePkg>,
    /// `(dependent, dependency)`: the dependent requires the dependency.
    pub requires: Vec<(String, String)>,
    pub essential: BTreeSet<String>,
    pub protected: BTreeSet<String>,
    pub scriptlet: FakeScriptlet,
    /// A package installed between the dry-run and the removing command:
    /// `(dependent, dependency)`. The dependent becomes installed.
    pub concurrent: Option<(String, String)>,
    /// The removing command also removes these packages (a defective tool).
    pub extra_removed: Vec<String>,
    /// Another process holds the package database lock.
    pub lock_busy: bool,
    /// Removing commands fail unless the caller is root (or uses sudo).
    pub enforce_root: bool,
    /// A live dnf process owns `/var/lib/dnf/rpmdb_lock.pid`.
    pub dnf_lock_holder: bool,
    /// dpkg is configured (dpkg.cfg / DPKG_FORCE) to ignore dependency
    /// problems unless the command line says `--refuse-depends`.
    pub force_depends_config: bool,
    /// dpkg ignores `--refuse-*` on the command line (a defective tool); only
    /// meaningful together with `force_depends_config`.
    pub ignore_refuse_flags: bool,
    /// dpkg status strings that differ from `install ok installed`; a real
    /// dpkg leaves `deinstall ok installed` behind when a removal is refused
    /// after it recorded the request, and `half-installed` after a failing
    /// post-removal script.
    pub dpkg_status: BTreeMap<String, String>,
    /// Lines `apt-get check` reports regardless of removals.
    pub check_noise: Vec<String>,
    pub kernel_release: Option<String>,
    /// The installed package that owns the running kernel's image.
    pub kernel_owner: Option<String>,
    /// persistdir line of dnf.conf is handled through `dnf_conf`.
    /// Contents of the DNF protected-package files; `None` models the
    /// directories not existing.
    pub dnf_protected_d: Option<String>,
    pub dnf_conf: Option<String>,
    /// `/etc/dnf/automatic.conf`; `None` models the file not existing.
    pub automatic_conf: Option<String>,
    /// Lines `dpkg --audit` / `rpm -Va` report regardless of removals.
    pub audit_noise: Vec<String>,
    /// Forced answers by command key, served first.
    pub overrides: BTreeMap<String, VecDeque<Output>>,
}

fn out(code: i32, stdout: impl Into<String>, stderr: impl Into<String>) -> Output {
    Output {
        completion: Completion::Exited(code),
        stdout: stdout.into().into_bytes(),
        stderr: stderr.into().into_bytes(),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}

impl FakePkgDb {
    /// A forced answer for a command key (see [`FakePkgDb::serve`]).
    pub fn force(&mut self, key: &str, output: Output) {
        self.overrides
            .entry(key.to_string())
            .or_default()
            .push_back(output);
    }

    pub fn add_requires(&mut self, dependent: &str, dependency: &str) {
        self.requires
            .push((dependent.to_string(), dependency.to_string()));
    }

    fn dependents_of(&self, installed: &BTreeSet<String>, target: &str) -> Vec<String> {
        let mut found: Vec<String> = self
            .requires
            .iter()
            .filter(|(dep, on)| on == target && dep != target && installed.contains(dep))
            .map(|(dep, _)| dep.clone())
            .collect();
        found.sort();
        found.dedup();
        found
    }

    fn apt_fields(&self, name: &str) -> (String, String, String) {
        let m = self.meta.get(name).cloned().unwrap_or_default();
        (
            m.status
                .unwrap_or_else(|| "install ok installed".to_string()),
            m.arch.unwrap_or_else(|| "amd64".to_string()),
            m.version.unwrap_or_else(|| "1.0-1".to_string()),
        )
    }

    fn rpm_fields(&self, name: &str) -> (u32, String, String, String) {
        let m = self.meta.get(name).cloned().unwrap_or_default();
        (
            m.epoch.unwrap_or(0),
            m.version.unwrap_or_else(|| "1.0".to_string()),
            m.release.unwrap_or_else(|| "1.el9".to_string()),
            m.arch.unwrap_or_else(|| "x86_64".to_string()),
        )
    }

    fn rpm_nevra(&self, name: &str) -> String {
        let (_, v, r, a) = self.rpm_fields(name);
        format!("{}-{}-{}.{}", name, v, r, a)
    }

    /// Resolve an `rpm` operand: an installed name or an installed NEVRA.
    fn rpm_resolve(&self, installed: &BTreeSet<String>, operand: &str) -> Option<String> {
        if installed.contains(operand) {
            return Some(operand.to_string());
        }
        installed
            .iter()
            .find(|n| self.rpm_nevra(n) == operand)
            .cloned()
    }

    fn forced(&mut self, key: &str) -> Option<Output> {
        self.overrides.get_mut(key).and_then(VecDeque::pop_front)
    }

    /// Serve a modeled `dpkg`, `dpkg-query`, `rpm`, `find`, `cat` or `uname`
    /// command. `None` means the shape is not modeled here.
    pub fn serve(
        &mut self,
        installed: &mut BTreeSet<String>,
        is_root: bool,
        prog: &str,
        args: &[String],
    ) -> Option<Output> {
        let a: Vec<&str> = args.iter().map(String::as_str).collect();
        let key = match (prog, a.as_slice()) {
            ("dpkg-query", ["-W", fmt, "--", _])
                if *fmt == "-f=${Status}\\t${Package}\\t${Architecture}\\n" =>
            {
                "dpkg-instances"
            }
            ("dpkg-query", ["-W", fmt, "--", _])
                if fmt.starts_with("-f=${Status}\\t${Package}") =>
            {
                "dpkg-identity"
            }
            ("dpkg-query", ["-W", fmt]) if fmt.starts_with("-f=${Status}\\t${Package}") => {
                "dpkg-inventory"
            }
            ("dpkg-query", ["-W", "-f=${Status}", "--", n])
                if self.dpkg_status.contains_key(*n)
                    || self
                        .meta
                        .get(*n)
                        .is_some_and(|m| !m.other_instances.is_empty()) =>
            {
                "dpkg-status"
            }
            ("dpkg", ["--audit"]) => "dpkg-audit",
            ("apt-get", ["-s", "check"]) => "apt-check",
            ("dpkg", rest) if rest.contains(&"--dry-run") && rest.contains(&"--remove") => {
                "dpkg-dry-run"
            }
            ("dpkg", rest) if rest.contains(&"--remove") => "dpkg-remove",
            ("rpm", ["-q", "--queryformat", fmt, "--", _]) if fmt.starts_with("%{NAME}\\t") => {
                "rpm-identity"
            }
            ("rpm", ["-qa", "--queryformat", _]) => "rpm-inventory",
            ("rpm", ["-Va", ..]) => "rpm-verify",
            ("rpm", ["-e", "--test", "--", _]) => "rpm-test",
            ("sh", ["-c", _, "sinter-erase", _]) => "rpm-erase",
            ("rpm", ["-qf", "--queryformat", _, "--", _]) => "rpm-owner",
            ("find", ["-L", first, ..]) if first.starts_with("/etc/yum/protected.d") => {
                "protected-d"
            }
            ("cat", ["--", "/etc/dnf/dnf.conf"]) => "dnf-conf",
            ("cat", ["--", "/etc/dnf/automatic.conf"]) => "automatic-conf",
            ("uname", ["-r"]) => "uname-r",
            _ => return None,
        };
        if let Some(forced) = self.forced(key) {
            return Some(forced);
        }
        let last = a.last().copied().unwrap_or("");
        Some(match key {
            "dpkg-identity" => self.dpkg_identity(installed, last),
            "dpkg-inventory" => self.dpkg_inventory(installed),
            "dpkg-audit" => out(
                0,
                self.audit_noise.join("\n") + &self.nl(&self.audit_noise),
                "",
            ),
            "dpkg-status" => self.dpkg_status_answer(installed, last),
            "dpkg-instances" => self.dpkg_instances(installed, last),
            "apt-check" => self.apt_check(installed),
            "dpkg-dry-run" => {
                let refuse = a.contains(&"--refuse-depends") && !self.ignore_refuse_flags;
                self.dpkg_remove(installed, last, true, refuse)
            }
            "dpkg-remove" => {
                if self.enforce_root && !is_root {
                    out(
                        2,
                        "",
                        "dpkg: error: requested operation requires superuser privilege\n",
                    )
                } else {
                    let refuse = a.contains(&"--refuse-depends") && !self.ignore_refuse_flags;
                    let name = a.last().copied().unwrap_or("");
                    self.dpkg_remove(installed, name, false, refuse)
                }
            }
            "rpm-identity" => self.rpm_identity(installed, last),
            "rpm-inventory" => self.rpm_inventory(installed),
            "rpm-verify" => self.rpm_verify(installed),
            "rpm-test" => self.rpm_erase(installed, last, true),
            "rpm-owner" => {
                let release = self
                    .kernel_release
                    .clone()
                    .unwrap_or_else(|| "5.14.0-1.el9.x86_64".to_string());
                let on_running = last.contains(&release);
                match &self.kernel_owner {
                    Some(owner) if on_running && installed.contains(owner) => {
                        out(0, format!("{}\n", owner), "")
                    }
                    _ => out(
                        1,
                        "",
                        format!("error: file {}: No such file or directory\n", last),
                    ),
                }
            }
            "rpm-erase" => {
                if self.dnf_lock_holder {
                    out(76, "", "")
                } else if self.enforce_root && !is_root {
                    out(
                        1,
                        "",
                        "error: can't create transaction lock on /var/lib/rpm/.rpm.lock (Permission denied)\n",
                    )
                } else {
                    self.rpm_erase(installed, last, false)
                }
            }
            "protected-d" => match &self.dnf_protected_d {
                Some(text) => out(0, text.clone(), ""),
                None => out(
                    1,
                    "",
                    "find: '/etc/yum/protected.d': No such file or directory\n\
                     find: '/etc/dnf/protected.d': No such file or directory\n",
                ),
            },
            "dnf-conf" => match &self.dnf_conf {
                Some(text) => out(0, text.clone(), ""),
                None => out(0, "[main]\ngpgcheck=1\ninstallonly_limit=3\n", ""),
            },
            "automatic-conf" => match &self.automatic_conf {
                Some(text) => out(0, text.clone(), ""),
                None => out(
                    1,
                    "",
                    "cat: /etc/dnf/automatic.conf: No such file or directory\n",
                ),
            },
            "uname-r" => out(
                0,
                format!(
                    "{}\n",
                    self.kernel_release
                        .clone()
                        .unwrap_or_else(|| "5.14.0-1.el9.x86_64".to_string())
                ),
                "",
            ),
            _ => return None,
        })
    }

    fn nl(&self, lines: &[String]) -> String {
        if lines.is_empty() {
            String::new()
        } else {
            "\n".to_string()
        }
    }

    // ---------------------------------------------------------------- dpkg

    /// What `dpkg-query -W -f=${Status} -- NAME` prints: one status per
    /// instance, run together without a separator.
    fn dpkg_status_answer(&self, installed: &BTreeSet<String>, name: &str) -> Output {
        let others = self
            .meta
            .get(name)
            .map(|m| m.other_instances.clone())
            .unwrap_or_default();
        if others.is_empty() {
            return out(
                0,
                self.dpkg_status.get(name).cloned().unwrap_or_default(),
                "",
            );
        }
        let mut text = String::new();
        if installed.contains(name) {
            text.push_str(
                &self
                    .dpkg_status
                    .get(name)
                    .cloned()
                    .unwrap_or_else(|| "install ok installed".to_string()),
            );
        }
        for (_, status) in &others {
            text.push_str(status);
        }
        out(0, text, "")
    }

    /// `dpkg-query -W -f=${Status}\t${Package}\t${Architecture}\n -- NAME`.
    fn dpkg_instances(&self, installed: &BTreeSet<String>, name: &str) -> Output {
        let mut text = String::new();
        if installed.contains(name) {
            let (mut status, arch, _) = self.apt_fields(name);
            if let Some(over) = self.dpkg_status.get(name) {
                status = over.clone();
            }
            text.push_str(&format!("{}\t{}\t{}\n", status, name, arch));
        }
        if let Some(m) = self.meta.get(name) {
            for (arch, _) in &m.duplicates {
                text.push_str(&format!("install ok installed\t{}\t{}\n", name, arch));
            }
            for (arch, status) in &m.other_instances {
                text.push_str(&format!("{}\t{}\t{}\n", status, name, arch));
            }
        }
        if text.is_empty() {
            return out(
                1,
                "",
                format!("dpkg-query: no packages found matching {}\n", name),
            );
        }
        out(0, text, "")
    }

    fn dpkg_identity(&self, installed: &BTreeSet<String>, name: &str) -> Output {
        if !installed.contains(name) {
            return out(
                1,
                "",
                format!("dpkg-query: no packages found matching {}\n", name),
            );
        }
        let (mut status, arch, version) = self.apt_fields(name);
        if let Some(over) = self.dpkg_status.get(name) {
            status = over.clone();
        }
        let yes_no = |set: &BTreeSet<String>| if set.contains(name) { "yes" } else { "" };
        let mut text = format!(
            "{}\t{}\t{}\t{}\t{}\t{}\n",
            status,
            name,
            arch,
            version,
            yes_no(&self.essential),
            yes_no(&self.protected)
        );
        if let Some(m) = self.meta.get(name) {
            for (dup_arch, dup_version) in &m.duplicates {
                text.push_str(&format!(
                    "install ok installed\t{}\t{}\t{}\t\t\n",
                    name, dup_arch, dup_version
                ));
            }
            for (other_arch, other_status) in &m.other_instances {
                text.push_str(&format!(
                    "{}\t{}\t{}\t1.0-1\t\t\n",
                    other_status, name, other_arch
                ));
            }
        }
        out(0, text, "")
    }

    fn dpkg_inventory(&self, installed: &BTreeSet<String>) -> Output {
        let mut text = String::from(
            "deinstall ok config-files\tleftover\tamd64\ninstall ok installed\tbase-files\tamd64\n",
        );
        for name in installed {
            let (_, arch, _) = self.apt_fields(name);
            let status = self
                .dpkg_status
                .get(name)
                .cloned()
                .unwrap_or_else(|| "install ok installed".to_string());
            text.push_str(&format!("{}\t{}\t{}\n", status, name, arch));
            if let Some(m) = self.meta.get(name) {
                for (other_arch, other_status) in &m.other_instances {
                    text.push_str(&format!("{}\t{}\t{}\n", other_status, name, other_arch));
                }
            }
        }
        out(0, text, "")
    }

    fn apt_check(&self, installed: &BTreeSet<String>) -> Output {
        let mut lines: Vec<String> = self.check_noise.clone();
        for (dependent, dependency) in &self.requires {
            if installed.contains(dependent) && !installed.contains(dependency) {
                lines.push(format!(
                    " {} : Depends: {} but it is not installed",
                    dependent, dependency
                ));
            }
        }
        let head =
            "Reading package lists...\nBuilding dependency tree...\nReading state information...\n";
        if lines.is_empty() {
            out(0, head, "")
        } else {
            out(
                100,
                format!(
                    "{head}The following packages have unmet dependencies:\n{}\n",
                    lines.join("\n")
                ),
                "E: Unmet dependencies. Try 'apt --fix-broken install' with no packages (or specify a solution).\n",
            )
        }
    }

    /// `dpkg --remove` / `dpkg --dry-run --remove`.
    ///
    /// A dry-run reads the database without locking it. The real run takes the
    /// locks first (without waiting), then records the request
    /// (`deinstall ok installed`) *before* it checks essential/protected
    /// status, dependencies and the pre-removal script, so a refusal after the
    /// locks leaves that selection behind (dpkg 1.22 `deferred_remove`).
    fn dpkg_remove(
        &mut self,
        installed: &mut BTreeSet<String>,
        name: &str,
        dry: bool,
        refuse_depends: bool,
    ) -> Output {
        if self.lock_busy && !dry {
            return out(
                2,
                "",
                "dpkg: error: dpkg frontend lock was locked by another process with pid 4242\n\
                 Note: removing the lock file is always wrong, and can end up in data loss.\n",
            );
        }
        if !installed.contains(name) {
            return out(
                0,
                "",
                format!(
                    "dpkg: warning: ignoring request to remove {} which isn't installed\n",
                    name
                ),
            );
        }
        if !dry {
            if let Some((dependent, dependency)) = self.concurrent.take() {
                installed.insert(dependent.clone());
                self.requires.push((dependent, dependency));
            }
            self.dpkg_status
                .insert(name.to_string(), "deinstall ok installed".to_string());
        }
        if self.essential.contains(name) {
            return out(
                1,
                "",
                format!(
                    "dpkg: error processing package {} (--remove):\n this is an essential \
                     package - it should not be removed\nErrors were encountered while \
                     processing:\n {}\n",
                    name, name
                ),
            );
        }
        let dependents = self.dependents_of(installed, name);
        let mut forced_notice = String::new();
        if !dependents.is_empty() {
            let mut text = format!("dpkg: dependency problems prevent removal of {}:\n", name);
            for d in &dependents {
                text.push_str(&format!(" {} depends on {}.\n", d, name));
            }
            if self.force_depends_config && !refuse_depends {
                forced_notice =
                    "dpkg: dependency problems, but removing anyway as you requested:\n"
                        .to_string();
                for d in &dependents {
                    forced_notice.push_str(&format!(" {} depends on {}.\n", d, name));
                }
            } else {
                text.push_str(&format!(
                    "\ndpkg: error processing package {} (--remove):\n dependency problems - not \
                     removing\nErrors were encountered while processing:\n {}\n",
                    name, name
                ));
                return out(1, "", text);
            }
        }
        let (_, _, version) = self.apt_fields(name);
        if dry {
            return out(
                0,
                format!(
                    "(Reading database ... 12345 files and directories currently installed.)\n\
                     Would remove or purge {} ({}) ...\n",
                    name, version
                ),
                forced_notice,
            );
        }
        let listing = format!(
            "(Reading database ... 12345 files and directories currently installed.)\nRemoving {} ({}) ...\n",
            name, version
        );
        match self.scriptlet {
            FakeScriptlet::PreRemoveFails => {
                // The pre-removal script failed: the package stays installed,
                // the removal request stays recorded.
                return out(
                    1,
                    "",
                    format!(
                        "dpkg: error processing package {} (--remove):\n installed {} package \
                         pre-removal script subprocess returned error exit status 1\n",
                        name, name
                    ),
                );
            }
            FakeScriptlet::PostRemoveFails => {
                // Files are gone, the post-removal script failed: dpkg leaves
                // the package half-installed.
                self.dpkg_status
                    .insert(name.to_string(), "deinstall ok half-installed".to_string());
                return out(
                    1,
                    listing,
                    format!(
                        "dpkg: error processing package {} (--remove):\n installed {} package \
                         post-removal script subprocess returned error exit status 1\n",
                        name, name
                    ),
                );
            }
            FakeScriptlet::FailsAfterRemoval => {
                self.dpkg_status.remove(name);
                self.drop_installed(installed, name);
                return out(
                    1,
                    listing,
                    "dpkg: error: unexpected failure after removal\n",
                );
            }
            FakeScriptlet::RemovedByOther
            | FakeScriptlet::RemovedByOtherConfigFiles
            | FakeScriptlet::RemovedByOtherQualified
            | FakeScriptlet::RemovedByOtherQualifiedConfigFiles => {
                // dpkg only warns about a request for a package that is gone.
                let (qualified, config_files) = match self.scriptlet {
                    FakeScriptlet::RemovedByOtherConfigFiles => (false, true),
                    FakeScriptlet::RemovedByOtherQualified => (true, false),
                    FakeScriptlet::RemovedByOtherQualifiedConfigFiles => (true, true),
                    _ => (false, false),
                };
                self.dpkg_status.remove(name);
                self.drop_installed(installed, name);
                return out(0, "", self.dpkg_gone_warning(name, qualified, config_files));
            }
            FakeScriptlet::FailsAfterRemovalRepeatingRefusals => {
                self.dpkg_status.remove(name);
                self.drop_installed(installed, name);
                return out(
                    1,
                    listing,
                    format!(
                        "dpkg: dependency problems prevent removal of {name}:\n \
                         other depends on {name}.\n\
                         dpkg: error: dpkg frontend lock was locked by another process with pid 4242\n\
                         dpkg: error: requested operation requires superuser privilege\n"
                    ),
                );
            }
            FakeScriptlet::RefusedThenRemovedByOther => {
                self.dpkg_status.remove(name);
                self.drop_installed(installed, name);
                return out(
                    1,
                    "(Reading database ... 12345 files and directories currently installed.)\n",
                    format!(
                        "dpkg: dependency problems prevent removal of {name}:\n \
                         other depends on {name}.\n"
                    ),
                );
            }
            FakeScriptlet::GoneThenUnexplainedFailure => {
                self.dpkg_status.remove(name);
                self.drop_installed(installed, name);
                return out(2, "", "dpkg: error: something unexpected happened\n");
            }
            FakeScriptlet::PostRemoveWarns
            | FakeScriptlet::Ok
            | FakeScriptlet::NoisyScript
            | FakeScriptlet::ForgedWarning => {}
        }
        self.dpkg_status.remove(name);
        self.drop_installed(installed, name);
        if self.scriptlet == FakeScriptlet::NoisyScript {
            return out(
                0,
                listing,
                format!("postrm: helper isn't installed, skipping\n{forced_notice}"),
            );
        }
        if self.scriptlet == FakeScriptlet::ForgedWarning {
            return out(
                0,
                listing,
                format!(
                    "{}{forced_notice}",
                    self.dpkg_gone_warning(name, false, false)
                ),
            );
        }
        out(0, listing, forced_notice)
    }

    /// dpkg 1.22 `deferred_remove`: what `dpkg --remove NAME` says, and exits 0,
    /// for a package that is not (or no longer) installed.
    fn dpkg_gone_warning(&self, name: &str, qualified: bool, config_files: bool) -> String {
        let subject = if qualified {
            let (_, arch, _) = self.apt_fields(name);
            format!("{}:{}", name, arch)
        } else {
            name.to_string()
        };
        if config_files {
            format!(
                "dpkg: warning: ignoring request to remove {subject}, only the config\n \
                 files of which are on the system; use --purge to remove them too\n"
            )
        } else {
            format!("dpkg: warning: ignoring request to remove {subject} which isn't installed\n")
        }
    }

    fn drop_installed(&self, installed: &mut BTreeSet<String>, name: &str) {
        installed.remove(name);
        for extra in &self.extra_removed {
            installed.remove(extra);
        }
    }

    // ----------------------------------------------------------------- rpm

    fn rpm_record(&self, name: &str) -> String {
        let (epoch, version, release, arch) = self.rpm_fields(name);
        format!("{}\t{}\t{}\t{}\t{}\n", name, epoch, version, release, arch)
    }

    fn rpm_identity(&self, installed: &BTreeSet<String>, operand: &str) -> Output {
        let Some(name) = self.rpm_resolve(installed, operand) else {
            return out(1, format!("package {} is not installed\n", operand), "");
        };
        let mut text = self.rpm_record(&name);
        if operand == name {
            if let Some(m) = self.meta.get(&name) {
                for (dup_arch, dup_version) in &m.duplicates {
                    text.push_str(&format!(
                        "{}\t0\t{}\t1.el9\t{}\n",
                        name, dup_version, dup_arch
                    ));
                }
            }
        }
        out(0, text, "")
    }

    fn rpm_inventory(&self, installed: &BTreeSet<String>) -> Output {
        let mut text = String::from("gpg-pubkey\t(none)\nsetup\tnoarch\n");
        for name in installed {
            let (_, _, _, arch) = self.rpm_fields(name);
            text.push_str(&format!("{}\t{}\n", name, arch));
        }
        out(0, text, "")
    }

    fn rpm_verify(&self, installed: &BTreeSet<String>) -> Output {
        let mut lines: Vec<String> = self.audit_noise.clone();
        for (dependent, dependency) in &self.requires {
            if installed.contains(dependent) && !installed.contains(dependency) {
                lines.push(format!(
                    "Unsatisfied dependencies for {}:\n\t{}",
                    self.rpm_nevra(dependent),
                    dependency
                ));
            }
        }
        if lines.is_empty() {
            out(0, "", "")
        } else {
            out(1, lines.join("\n") + "\n", "")
        }
    }

    fn rpm_erase(&mut self, installed: &mut BTreeSet<String>, operand: &str, test: bool) -> Output {
        let Some(name) = self.rpm_resolve(installed, operand) else {
            return out(
                1,
                "",
                format!("error: package {} is not installed\n", operand),
            );
        };
        if self.lock_busy && !test {
            return out(
                1,
                "",
                "error: can't create transaction lock on /var/lib/rpm/.rpm.lock (Resource \
                 temporarily unavailable)\n",
            );
        }
        let dependents = self.dependents_of(installed, &name);
        if !dependents.is_empty() {
            let mut text = String::from("error: Failed dependencies:\n");
            for d in &dependents {
                text.push_str(&format!(
                    "\t{} is needed by (installed) {}\n",
                    name,
                    self.rpm_nevra(d)
                ));
            }
            return out(1, "", text);
        }
        if test {
            return out(0, "", "");
        }
        // rpm checked the dependencies above and does not check them again
        // when it takes the transaction lock: a package installed in between
        // is only seen by the verification afterwards.
        if let Some((dependent, dependency)) = self.concurrent.take() {
            installed.insert(dependent.clone());
            self.requires.push((dependent, dependency));
        }
        let nevra = self.rpm_nevra(&name);
        match self.scriptlet {
            FakeScriptlet::PreRemoveFails => out(
                1,
                "",
                format!(
                    "error: %preun({}) scriptlet failed, exit status 1\nerror: {}: erase failed\n",
                    nevra, nevra
                ),
            ),
            FakeScriptlet::PostRemoveFails => {
                self.drop_installed(installed, &name);
                out(
                    1,
                    "",
                    format!(
                        "error: %postun({}) scriptlet failed, exit status 1\n",
                        nevra
                    ),
                )
            }
            FakeScriptlet::PostRemoveWarns => {
                self.drop_installed(installed, &name);
                out(
                    0,
                    "",
                    format!(
                        "warning: %postun({}) scriptlet failed, exit status 1\n",
                        nevra
                    ),
                )
            }
            FakeScriptlet::FailsAfterRemoval
            | FakeScriptlet::FailsAfterRemovalRepeatingRefusals
            | FakeScriptlet::RefusedThenRemovedByOther
            | FakeScriptlet::GoneThenUnexplainedFailure => {
                self.drop_installed(installed, &name);
                out(1, "", "error: unexpected failure after erase\n")
            }
            FakeScriptlet::RemovedByOther
            | FakeScriptlet::RemovedByOtherConfigFiles
            | FakeScriptlet::RemovedByOtherQualified
            | FakeScriptlet::RemovedByOtherQualifiedConfigFiles => {
                self.drop_installed(installed, &name);
                out(
                    1,
                    "",
                    format!("error: package {} is not installed\n", nevra),
                )
            }
            FakeScriptlet::Ok => {
                self.drop_installed(installed, &name);
                out(0, "", "")
            }
            FakeScriptlet::NoisyScript => {
                self.drop_installed(installed, &name);
                out(0, "", "scriptlet: helper isn't installed, skipping\n")
            }
            FakeScriptlet::ForgedWarning => {
                self.drop_installed(installed, &name);
                out(
                    0,
                    "",
                    format!(
                        "dpkg: warning: ignoring request to remove {} which isn't installed\n",
                        name
                    ),
                )
            }
        }
    }
}
