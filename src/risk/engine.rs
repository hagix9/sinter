//! The engine side of connection-risk control (DESIGN §43).
//!
//! `Engine::run` calls [`Engine::risk_begin`] before anything else of a run:
//! the static gate (§43.2) and, when the run has enforced connection-risk
//! resources, the management path (§43.3). A connection-risk resource calls
//! [`Engine::risk_check_plugin`] after observing and before any mutation;
//! it records what plan reports and refuses what apply may not do.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value as J};

use super::approval::Store;
use super::path::{FwFacts, FwZone, NetFacts, PathState};
use super::rules::{self, Dynamic, FwChange, Recovery, RuleKind};
use super::{Enforcement, RiskClass, StaticItem};
use crate::engine::{Engine, Mode};
use crate::error::{Result, SinterError};
use crate::executor::Completion;

/// What the CLI tells the engine about the connection-risk context of one
/// execution.
#[derive(Debug, Clone, Default)]
pub struct RiskContext {
    /// Inventory name of the host (or the `--host` value).
    pub host: String,
    /// The administrator declared a direct local connection.
    pub loopback_declared: bool,
    /// The approval record for this host (apply with `--approval`).
    pub approval: Option<J>,
    /// Where keyed digests come from; `None`: no digests are computed.
    pub store: Option<Store>,
}

/// One connection-risk resource as plan or apply saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskRecord {
    pub id: String,
    pub type_: String,
    pub class: RiskClass,
    pub enforced: bool,
    pub dynamic: String,
    pub reason: Option<String>,
    pub change_digest: Option<String>,
    pub approved: bool,
    /// The planned operations and the desired values, for the approval
    /// prompt (values withheld for a sensitive resource).
    pub steps: Vec<String>,
    pub desired: std::collections::BTreeMap<String, String>,
}

/// What an engine leaves for the CLI after a run.
#[derive(Debug, Clone, Default)]
pub struct RiskLog {
    pub records: Vec<RiskRecord>,
    pub path: Option<String>,
    pub host_key_sha256: Option<String>,
    pub ssh_user: Option<String>,
    pub sudo: bool,
}

/// Per-run state.
#[derive(Debug, Default)]
pub struct RiskState {
    pub ctx: Option<RiskContext>,
    pub items: Vec<StaticItem>,
    pub path: Option<PathState>,
    pub earlier_change: bool,
    pub key: Option<Vec<u8>>,
    pub log: Arc<Mutex<RiskLog>>,
    /// Ids of sensitive connection-risk resources (reasons withheld).
    pub sensitive_ids: BTreeSet<String>,
}

/// Zone and interface names reported by firewalld before they are used in
/// argv: the plugin `ident` rule, so none can become an option.
fn safe_name(s: &str) -> bool {
    crate::plugin::verify::operand_ok(s, 64)
}

fn stdout(o: &crate::executor::Output) -> Option<String> {
    if o.completion == Completion::Exited(0) && !o.stdout_truncated {
        String::from_utf8(o.stdout.clone()).ok()
    } else {
        None
    }
}

impl Engine {
    /// Install the connection-risk context of this execution (CLI).
    pub fn with_risk(mut self, ctx: RiskContext) -> Self {
        self.risk.ctx = Some(ctx);
        self
    }

    /// The log the CLI reads after `run` (shared, so it outlives the engine).
    pub fn risk_log(&self) -> Arc<Mutex<RiskLog>> {
        self.risk.log.clone()
    }

    /// Static gate and management path, before any resource (DESIGN §43.2,
    /// §43.3). Without a context, an R resource is refused (no approval).
    pub(crate) fn risk_begin(&mut self) -> Result<()> {
        let apply = self.opts.mode == Mode::Apply;
        let approved: Option<BTreeSet<String>> = if apply {
            Some(
                self.risk
                    .ctx
                    .as_ref()
                    .and_then(|c| c.approval.as_ref())
                    .and_then(|a| a["resources"].as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default(),
            )
        } else {
            None
        };
        let items = super::static_gate(&self.model, approved.as_ref())?;
        {
            let mut log = self.risk.log.lock().unwrap_or_else(|e| e.into_inner());
            log.host_key_sha256 = self.fs.host_key_sha256();
            log.ssh_user = self.fs.ssh_user();
            log.sudo = self.opts.sudo;
        }
        if let Some(store) = self.risk.ctx.as_ref().and_then(|c| c.store.clone()) {
            self.risk.key = Some(store.key()?);
        }
        let needs_path = items.iter().any(|i| {
            i.enforcement == Enforcement::Enforced
                && i.class != RiskClass::N
                && i.rule != RuleKind::None
        });
        self.risk.items = items;
        if needs_path {
            let firewalld = self.risk.items.iter().any(|i| {
                matches!(
                    i.rule,
                    RuleKind::FwServiceAbsent
                        | RuleKind::FwPortAbsent
                        | RuleKind::FwProtocolAbsent
                        | RuleKind::FwInterface
                        | RuleKind::FwSource
                        | RuleKind::FwZoneAbsent
                        | RuleKind::FwReload
                )
            });
            let p = self.risk_management_path(firewalld);
            self.risk.log.lock().unwrap_or_else(|e| e.into_inner()).path = Some(match &p {
                PathState::Known(m) => format!(
                    "interfaces={} zone={:?}",
                    m.ifaces.iter().cloned().collect::<Vec<_>>().join(","),
                    m.zone
                ),
                PathState::Unknown(why) => format!("unknown: {}", why),
            });
            self.risk.path = Some(p);
        }
        Ok(())
    }

    /// Observe the management path (read-only).
    fn risk_management_path(&mut self, firewalld: bool) -> PathState {
        let declared = self
            .risk
            .ctx
            .as_ref()
            .map(|c| c.loopback_declared)
            .unwrap_or(false);
        let mut n = NetFacts {
            ssh_connection: self.fs.probe_ssh_connection(),
            loopback_declared: declared,
            ..Default::default()
        };
        let parsed = n
            .ssh_connection
            .as_deref()
            .and_then(super::path::parse_ssh_connection);
        if let Some((client, _, server, _)) = parsed {
            if !(client.is_loopback() && server.is_loopback()) {
                n.ss = self
                    .fs
                    .risk_observe("/usr/bin/ss", &["-Htn", "state", "established"])
                    .ok()
                    .and_then(|o| stdout(&o));
                n.ip_addr = self
                    .fs
                    .risk_observe("/usr/sbin/ip", &["-o", "addr", "show"])
                    .ok()
                    .and_then(|o| stdout(&o));
                let (c, s) = (client.to_string(), server.to_string());
                n.route = self
                    .fs
                    .risk_observe("/usr/sbin/ip", &["-o", "route", "get", &c, "from", &s])
                    .ok()
                    .and_then(|o| stdout(&o));
            }
        }
        let state = super::path::determine(&n);
        if !firewalld {
            return state;
        }
        let facts = match &state {
            PathState::Known(p) if !p.loopback => Some(self.risk_firewalld_facts(&p.ifaces)),
            _ => None,
        };
        super::path::with_zone(state, facts.as_ref())
    }

    fn fw(&mut self, args: &[&str]) -> Option<String> {
        self.fs
            .risk_observe("/usr/bin/firewall-cmd", args)
            .ok()
            .and_then(|o| stdout(&o))
    }

    fn risk_firewalld_facts(&mut self, ifaces: &BTreeSet<String>) -> FwFacts {
        let state = self.fs.risk_observe("/usr/bin/firewall-cmd", &["--state"]);
        let running = matches!(&state, Ok(o) if o.completion == Completion::Exited(0));
        if !running {
            // Not running (252) is a fact; a failed query is unknown.
            return match state {
                Ok(o) if o.completion == Completion::Exited(252) => FwFacts::default(),
                _ => FwFacts {
                    running: true,
                    ..Default::default()
                },
            };
        }
        let mut f = FwFacts {
            running: true,
            version: self.fw(&["--version"]).map(|s| s.trim().to_string()),
            default_zone: self
                .fw(&["--get-default-zone"])
                .map(|s| s.trim().to_string())
                .filter(|z| safe_name(z)),
            ..Default::default()
        };
        let modern = f
            .version
            .as_deref()
            .and_then(|v| v.split('.').next())
            .and_then(|m| m.parse::<u32>().ok())
            .map(|m| m >= 2)
            .unwrap_or(true);
        if let Some(list) = self.fw(&["--get-zones"]) {
            let mut zones = Vec::new();
            let mut ok = true;
            for z in list.split_whitespace() {
                if !safe_name(z) {
                    ok = false;
                    break;
                }
                let zarg = format!("--zone={}", z);
                let Some(src) = self.fw(&[&zarg, "--list-sources"]) else {
                    ok = false;
                    break;
                };
                let Some(fwd) = self.fw(&[&zarg, "--list-forward-ports"]) else {
                    ok = false;
                    break;
                };
                let prio = match self
                    .fs
                    .risk_observe("/usr/bin/firewall-cmd", &[&zarg, "--get-priority"])
                {
                    Ok(o) if o.completion == Completion::Exited(0) => stdout(&o)
                        .and_then(|s| s.trim().parse::<i64>().ok())
                        .map(|n| Ok(Some(n)))
                        .unwrap_or(Err(())),
                    // A version without zone priorities rejects the option.
                    Ok(o) if !modern && matches!(o.completion, Completion::Exited(_)) => Ok(None),
                    _ => Err(()),
                };
                zones.push(FwZone {
                    name: z.to_string(),
                    sources: src.split_whitespace().map(str::to_string).collect(),
                    forward_ports: !fwd.trim().is_empty(),
                    priority: prio,
                });
            }
            if ok {
                f.zones = Some(zones);
            }
        }
        f.extra_rules = match (
            self.fw(&["--get-active-policies"]),
            self.fw(&["--direct", "--get-all-rules"]),
        ) {
            (Some(pol), Some(direct)) => {
                let extra_policy = pol.split_whitespace().any(|p| p != "allow-host-ipv6");
                Some(extra_policy || !direct.trim().is_empty())
            }
            _ => None,
        };
        for i in ifaces {
            let q = format!("--get-zone-of-interface={}", i);
            let ans = if safe_name(i) {
                match self.fs.risk_observe("/usr/bin/firewall-cmd", &[&q]) {
                    Ok(o) if o.completion == Completion::Exited(0) => match stdout(&o) {
                        Some(z) if safe_name(z.trim()) => Ok(Some(z.trim().to_string())),
                        _ => Err(()),
                    },
                    // `no zone` answers exit 2 (INVALID_ARGUMENT/ZONE_CONFLICT
                    // differ by version: anything but this exact answer is
                    // unknown).
                    Ok(o)
                        if o.completion == Completion::Exited(2)
                            && String::from_utf8_lossy(&o.stdout).trim() == "no zone" =>
                    {
                        Ok(None)
                    }
                    _ => Err(()),
                }
            } else {
                Err(())
            };
            f.iface_zones.push((i.clone(), ans));
        }
        f
    }

    fn risk_key(&self) -> Option<&[u8]> {
        self.risk.key.as_deref()
    }

    /// The connection-risk check of a plugin resource, after observing and
    /// before any mutation (DESIGN §43.3, §43.4). Returns a note for the
    /// result; an `Err` refuses the resource with nothing changed.
    pub(crate) fn risk_check_plugin(
        &mut self,
        res: &crate::model::FrozenResource,
        values: &std::collections::BTreeMap<String, String>,
        facets: &[(String, String, String)],
        pending_ops: &[String],
    ) -> Result<Option<String>> {
        let Some(item) = self.risk.items.iter().find(|i| i.id == res.id).cloned() else {
            return Ok(None);
        };
        let sensitive = res.sensitive || res.derived_sensitive;
        if sensitive {
            self.risk.sensitive_ids.insert(res.id.clone());
        }
        let shown = |s: String| {
            if sensitive {
                "[redacted]".to_string()
            } else {
                s
            }
        };
        let apply = self.opts.mode == Mode::Apply;
        let digest = self.risk_key().map(|k| {
            let v = json!({
                "id": res.id,
                "type": res.type_,
                "class": item.class.label(),
                "desired": values,
                "facets": facets.iter().map(|(n, o, w)| json!({"name": n, "observed": o, "want": w})).collect::<Vec<_>>(),
                "steps": pending_ops,
            });
            super::approval::keyed(k, &v)
        });
        let mut record = RiskRecord {
            id: res.id.clone(),
            type_: res.type_.clone(),
            class: item.class,
            enforced: item.enforcement == Enforcement::Enforced,
            dynamic: String::new(),
            reason: None,
            change_digest: digest.clone(),
            approved: false,
            steps: pending_ops.to_vec(),
            desired: values
                .iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        if sensitive {
                            "[redacted]".to_string()
                        } else {
                            v.clone()
                        },
                    )
                })
                .collect(),
        };
        if let Enforcement::PendingOwner(d) = item.enforcement {
            record.dynamic = "not-enforced".into();
            record.reason = Some(format!(
                "connection-risk control for {} is not in force (Owner decision {} pending)",
                item.source, d
            ));
            let note = format!(
                "connection-risk class={} not enforced ({}: Owner decision {} pending)",
                item.class.label(),
                item.source,
                d
            );
            self.risk_push(record);
            return Ok(Some(note));
        }
        let dynamic = if pending_ops.is_empty() {
            Dynamic::NoChange
        } else if self.risk.earlier_change {
            if apply {
                Dynamic::Unknown("an earlier connection-risk change of this run".into())
            } else {
                Dynamic::Deferred
            }
        } else if item.class == RiskClass::N || item.rule == RuleKind::None {
            Dynamic::Clear
        } else {
            let path = self
                .risk
                .path
                .clone()
                .unwrap_or_else(|| PathState::Unknown("not determined".into()));
            let change = self.risk_fw_change(item.rule, values);
            match item.rule {
                RuleKind::NmConnection => {
                    Dynamic::Unknown("NetworkManager facts are not observed yet".into())
                }
                k => rules::firewalld(k, &path, &change),
            }
        };
        record.dynamic = dynamic.label().to_string();
        record.reason = match &dynamic {
            Dynamic::Affects(w) | Dynamic::Unknown(w) => Some(w.clone()),
            _ => None,
        };
        // Approval: the host's record covers this id with this change digest.
        let approval = self.risk.ctx.as_ref().and_then(|c| c.approval.clone());
        let approved = match (&approval, &digest) {
            (Some(a), Some(d)) => a["changes"].as_array().is_some_and(|ch| {
                ch.iter().any(|c| {
                    c["id"] == res.id.as_str()
                        && super::approval::same_digest(
                            c["change_digest"].as_str().unwrap_or(""),
                            d,
                        )
                })
            }),
            _ => false,
        };
        record.approved = approved;
        if apply {
            if let Some(a) = &approval {
                let listed = a["resources"]
                    .as_array()
                    .is_some_and(|r| r.iter().any(|x| x == res.id.as_str()));
                if listed && !approved && !matches!(dynamic, Dynamic::NoChange) {
                    record.dynamic = "refused".into();
                    record.reason = Some("the change differs from the approved change".into());
                    self.risk_push(record);
                    return Err(SinterError::apply(format!(
                        "{}: the change differs from the approved change (re-observed state or steps changed); nothing was changed",
                        res.id
                    )));
                }
            }
            match rules::decide(item.class, &dynamic, approved, Recovery::None, false) {
                rules::Decision::Proceed => {}
                rules::Decision::Guarded(_) => unreachable!("no guarded procedure in this version"),
                rules::Decision::Refuse(why) => {
                    record.dynamic = format!("{} (refused)", dynamic.label());
                    self.risk_push(record);
                    return Err(SinterError::apply(format!(
                        "{}: connection-risk control: {}; nothing was changed",
                        res.id,
                        shown(why)
                    )));
                }
            }
        }
        if !pending_ops.is_empty() {
            self.risk.earlier_change = true;
        }
        let note = format!(
            "connection-risk class={} dynamic={} approval={}",
            item.class.label(),
            dynamic.label(),
            if approved { "yes" } else { "no" }
        );
        self.risk_push(record);
        Ok(Some(note))
    }

    fn risk_push(&mut self, mut r: RiskRecord) {
        // A sensitive resource's reasons can name its values: withheld.
        if self.risk.sensitive_ids.contains(&r.id) && r.reason.is_some() {
            r.reason = Some("[redacted]".into());
        }
        self.risk
            .log
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .records
            .push(r);
    }

    /// The facts a firewalld rule needs, observed read-only.
    fn risk_fw_change(
        &mut self,
        rule: RuleKind,
        v: &std::collections::BTreeMap<String, String>,
    ) -> FwChange {
        let mut c = FwChange {
            zone: v.get("zone").cloned(),
            port: v.get("port").cloned(),
            protocol: v.get("protocol").cloned(),
            interface: v.get("interface").cloned(),
            source: v.get("source").cloned(),
            ..Default::default()
        };
        if rule == RuleKind::FwServiceAbsent {
            if let Some(s) = v.get("service").filter(|s| safe_name(s)) {
                let q = format!("--info-service={}", s);
                c.service_ports = self.fw(&[&q]).and_then(|text| {
                    text.lines()
                        .find_map(|l| l.trim().strip_prefix("ports:"))
                        .map(|p| p.split_whitespace().map(str::to_string).collect())
                });
            }
        }
        c
    }
}

/// The content object of a host's plan (DESIGN §43.4), from what plan or
/// the apply preflight produced. Every value derived from resource content
/// is keyed with the controller key.
pub fn content_object(
    store: &Store,
    key: &[u8],
    host: &str,
    model: &crate::model::Model,
    report: &crate::engine::RunReport,
    log: &RiskLog,
) -> J {
    let model_repr: Vec<J> = model
        .resources
        .iter()
        .map(|r| {
            json!({
                "id": r.id,
                "type": r.type_,
                "with": format!("{:?}", r.with),
                "when": r.when,
                "depends_on": r.depends_on,
                "notify": r.notify,
                "sensitive": r.sensitive,
                "loop_index": r.loop_index,
                "loop_item": format!("{:?}", r.loop_item),
            })
        })
        .collect();
    let model_digest = store.keyed(key, &json!({"resources": model_repr, "handlers": model.handlers.iter().map(|h| format!("{:?}", (&h.id, &h.kind, &h.service, &h.action, &h.command))).collect::<Vec<_>>()}));
    let resources: Vec<J> = report
        .resources
        .iter()
        .map(|r| {
            let risk = log.records.iter().rev().find(|x| x.id == r.id);
            json!({
                "id": r.id,
                "type": r.type_,
                "change": r.change.label(),
                "unknown": r.unknown,
                "diff_digest": store.keyed(key, &J::String(format!("{:?}", r.diff))),
                "class": risk.map(|x| x.class.label()).unwrap_or("-"),
                "dynamic": risk.map(|x| x.dynamic.clone()).unwrap_or_default(),
                "change_digest": risk.and_then(|x| x.change_digest.clone()),
                "steps": risk.map(|x| x.steps.clone()).unwrap_or_default(),
                "desired": risk.map(|x| json!(x.desired)).unwrap_or(J::Null),
            })
        })
        .collect();
    json!({
        "sinter_version": env!("CARGO_PKG_VERSION"),
        "host": host,
        "target": {
            "ssh_user": log.ssh_user,
            "sudo": log.sudo,
            "host_key_sha256": log.host_key_sha256,
        },
        "model_digest": model_digest,
        "resources": resources,
    })
}
