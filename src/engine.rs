use crate::error::{MutationState, Result, SinterError};
use crate::executor::{
    Completion, ExecRequest, Executor, LocalExecutor, Output, SshConfig, SshExecutor,
};
use crate::expressions::{eval_boolean, eval_value_interpolated, parse_expr, EvalVal, Scope};
use crate::facts::Facts;
use crate::model::{FrozenResource, Model};

use crate::result::*;
use crate::targetfs::TargetFs;
use crate::value::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Plan,
    Apply,
}

#[derive(Debug, Clone)]
pub struct TargetSpec {
    /// None means localhost.
    pub ssh: Option<SshSpec>,
}

#[derive(Debug, Clone)]
pub struct SshSpec {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub known_hosts: PathBuf,
    pub identity_files: Vec<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct RunOptions {
    pub mode: Mode,
    pub sudo: bool,
    pub target: TargetSpec,
    pub verbose: bool,
    /// Test-only controlled failure-injection point around publication.
    pub fault: Option<String>,
}

pub struct RunReport {
    pub resources: Vec<ResourceResult>,
    pub handlers_run: Vec<HandlerResult>,
    pub handlers_pending: Vec<String>,
    pub facts: Facts,
    pub status: AggregateStatus,
    /// Full audit log of raw command invocations (instrumentation).
    pub commands: Vec<crate::executor::CommandRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AggregateStatus {
    Success,
    PlanError,
    ApplyFailed,
    Indeterminate,
}

pub struct Engine {
    pub(crate) model: Model,
    pub(crate) fs: TargetFs,
    pub(crate) facts: Facts,
    pub(crate) vars: BTreeMap<String, EvalVal>,
    pub(crate) registers: BTreeMap<String, EvalVal>,
    pub(crate) opts: RunOptions,
}

impl Engine {
    pub fn new(model: Model, opts: RunOptions) -> Result<Self> {
        let mut ex = build_executor(&opts)?;
        ex = connect_and_prepare(ex, opts.sudo)?;
        let has_getfattr = command_present(&mut ex, "/usr/bin/getfattr")?;
        let has_getfacl = command_present(&mut ex, "/usr/bin/getfacl")?;
        let (facts, target_uid, target_gid, home) = gather_target_info(&mut ex, opts.sudo)?;
        let mut vars = BTreeMap::new();
        for (name, v) in &model.vars {
            vars.insert(
                name.clone(),
                if v.sensitive {
                    EvalVal::known_sensitive(v.value.clone())
                } else {
                    EvalVal::known(v.value.clone())
                },
            );
        }
        Ok(Engine {
            model,
            fs: TargetFs::new_for(
                ex,
                opts.sudo,
                target_uid,
                target_gid,
                home,
                has_getfattr,
                has_getfacl,
                opts.mode == Mode::Apply,
                opts.fault.clone(),
            ),
            facts,
            vars,
            registers: BTreeMap::new(),
            opts,
        })
    }

    /// Internal execution audit log for acceptance/instrumentation tests.
    pub fn execution_log(&self) -> Vec<crate::executor::CommandRecord> {
        self.fs.log()
    }

    pub fn run(mut self) -> Result<RunReport> {
        let order = execution_order(&self.model)?;
        let mut results: BTreeMap<String, usize> = BTreeMap::new();
        let mut out_results: Vec<ResourceResult> = Vec::new();
        // Handlers queued for the handler phase. The bool records whether the
        // queueing change was sensitive, so handler presentation can be
        // conservatively redacted.
        let mut notified: BTreeMap<String, bool> = BTreeMap::new();
        let mut stopped = false;
        let mut stop_reason: Option<String> = None;

        for (pos, ridx) in order.iter().enumerate() {
            let res = self.model.resources[*ridx].clone();
            if stopped {
                let mut r = blocked_fail_fast(&res);
                r.reason = stop_reason.clone();
                results.insert(res.id.clone(), out_results.len());
                out_results.push(r);
                continue;
            }

            // Evaluate the resource's own condition BEFORE dependency gating.
            // A false condition makes the resource skipped_by_condition
            // regardless of its dependencies (DESIGN §9, §14). This also means
            // a false condition short-circuits an Unknown dependency: the
            // outcome is resolved by the condition.
            let item = res.loop_item.as_ref().map(|v| EvalVal::known(v.clone()));
            let when_result = match self.eval_condition(&res, item.as_ref()) {
                Ok(w) => w,
                Err(e) => {
                    if self.opts.mode == Mode::Plan {
                        return Err(SinterError::plan(e.message));
                    }
                    let r = failed_result_from_error(&res, &e);
                    stopped = true;
                    stop_reason = Some(r.reason.clone().unwrap_or_default());
                    results.insert(res.id.clone(), out_results.len());
                    out_results.push(r);
                    continue;
                }
            };
            match when_result {
                Some(false) => {
                    results.insert(res.id.clone(), out_results.len());
                    out_results.push(ResourceResult::skipped(&res.id, &res.type_, &res.origin));
                    continue;
                }
                None => {
                    if self.opts.mode == Mode::Apply {
                        let mut r = failed_result_from_error(
                            &res,
                            &SinterError::apply(format!(
                                "{}: when evaluated to Unknown in apply; refusing to mutate",
                                res.id
                            )),
                        );
                        r.execution = Execution::Failed;
                        r.reason = Some(format!(
                            "{}: when evaluated to Unknown in apply; refusing to mutate",
                            res.id
                        ));
                        stopped = true;
                        stop_reason = r.reason.clone();
                        results.insert(res.id.clone(), out_results.len());
                        out_results.push(r);
                        continue;
                    }
                    let mut r = unknown_result(&res);
                    r.reason = Some("condition is Unknown in plan".into());
                    results.insert(res.id.clone(), out_results.len());
                    out_results.push(r);
                    continue;
                }
                Some(true) => {}
            }

            // Check dependencies (after the condition resolved true).
            let mut dep_failure: Option<String> = None;
            let mut dep_unknown = false;
            for dep in &res.depends_on {
                match results.get(dep).and_then(|i| out_results.get(*i)) {
                    Some(dr) if dr.satisfies_dependency() => {}
                    Some(dr) if dr.is_unknown_dependency() => {
                        dep_unknown = true;
                        dep_failure = Some(format!(
                            "dependency {} is unknown ({})",
                            dep,
                            dr.reason.clone().unwrap_or_default()
                        ));
                        break;
                    }
                    Some(dr) => {
                        dep_failure = Some(format!(
                            "dependency {} is {} ({})",
                            dep,
                            dr.disposition.label(),
                            dr.reason.clone().unwrap_or_default()
                        ));
                        break;
                    }
                    None => {
                        dep_failure = Some(format!("dependency {} was not processed", dep));
                        break;
                    }
                }
            }
            if let Some(reason) = dep_failure {
                let mut r = blocked_by_dependency(&res, &reason);
                if dep_unknown {
                    r.unknown = true;
                    r.disposition = Disposition::Normal;
                    r.reason = Some(reason);
                }
                results.insert(res.id.clone(), out_results.len());
                out_results.push(r);
                continue;
            }

            let rr = match self.dispatch_resource(&res, item.as_ref()) {
                Ok(r) => r,
                Err(e) => {
                    if self.opts.mode == Mode::Plan {
                        // Any failure to complete observation safely in plan is
                        // a plan error (exit 4).
                        return Err(SinterError::plan(e.message));
                    }
                    failed_result_from_error(&res, &e)
                }
            };
            let is_stop = rr.is_failure() || rr.is_indeterminate();
            if is_stop {
                stopped = true;
                stop_reason = Some(rr.reason.clone().unwrap_or_else(|| {
                    if rr.is_indeterminate() {
                        "resource became indeterminate".into()
                    } else {
                        "resource failed".into()
                    }
                }));
            }
            // Queue handler notifications for definitely-changed verified resources.
            if !is_stop
                && rr.change == Change::Changed
                && rr.execution == Execution::Succeeded
                && rr.verification != Verification::Failed
                && rr.verification != Verification::Unknown
            {
                for h in &res.notify {
                    let entry = notified.entry(h.clone()).or_insert(false);
                    *entry = *entry || res.sensitive;
                }
            }
            results.insert(res.id.clone(), out_results.len());
            out_results.push(rr);
            let _ = pos;
        }

        let mut handlers_run = Vec::new();
        let mut handlers_pending = Vec::new();
        if self.opts.mode == Mode::Plan {
            // Plan never executes handlers; every notified handler is reported
            // as pending (would-run) without touching the target.
            for id in notified.keys() {
                handlers_pending.push(id.clone());
            }
        } else if !stopped {
            // Handler phase in declaration order.
            let mut ids: Vec<&String> = notified.keys().collect();
            ids.sort_by_key(|id| {
                self.model
                    .handler_index
                    .get(*id)
                    .copied()
                    .unwrap_or(usize::MAX)
            });
            let mut hstopped = false;
            let mut hstop_reason: Option<String> = None;
            for id in ids {
                let hi = self.model.handler_index[id];
                let mut h = self.model.handlers[hi].clone();
                // A handler queued by a sensitive resource is treated as
                // sensitive for presentation purposes.
                if *notified.get(id).unwrap_or(&false) {
                    h.sensitive = true;
                }
                if hstopped {
                    handlers_pending.push(id.clone());
                    let _ = hstop_reason.take();
                    continue;
                }
                let action = match h.action {
                    crate::ir::HandlerAction::Restart => "restart",
                    crate::ir::HandlerAction::Reload => "reload",
                };
                // Outer errors must not discard already-processed resources or
                // pending handler information. Convert them into a handler
                // outcome and continue building the report.
                let hr = match self.run_handler(&h) {
                    Ok(hr) => hr,
                    Err(e) => {
                        let state = if e.kind == crate::error::ErrorKind::Indeterminate {
                            HandlerOutcomeState::Indeterminate
                        } else {
                            HandlerOutcomeState::Failed
                        };
                        HandlerResult {
                            id: h.id.clone(),
                            service: h.service.clone(),
                            action: action.to_string(),
                            state,
                            reason: Some(e.message.clone()),
                            sensitive: h.sensitive,
                        }
                    }
                };
                let stop = matches!(
                    hr.state,
                    HandlerOutcomeState::Failed | HandlerOutcomeState::Indeterminate
                );
                if stop {
                    hstopped = true;
                    hstop_reason = hr.reason.clone();
                }
                handlers_run.push(hr);
            }
        } else {
            for id in notified.keys() {
                handlers_pending.push(id.clone());
            }
        }

        let handler_failed = handlers_run
            .iter()
            .any(|h| h.state == HandlerOutcomeState::Failed);
        let handler_indeterminate = handlers_run
            .iter()
            .any(|h| h.state == HandlerOutcomeState::Indeterminate);

        let status = if self.opts.mode == Mode::Plan {
            if out_results
                .iter()
                .any(|r| r.is_failure() || r.is_indeterminate())
            {
                AggregateStatus::PlanError
            } else {
                AggregateStatus::Success
            }
        } else if handler_indeterminate || out_results.iter().any(|r| r.is_indeterminate()) {
            AggregateStatus::Indeterminate
        } else if handler_failed || out_results.iter().any(|r| r.is_failure()) {
            AggregateStatus::ApplyFailed
        } else {
            AggregateStatus::Success
        };

        let commands = self.fs.log();
        Ok(RunReport {
            resources: out_results,
            handlers_run,
            handlers_pending,
            facts: self.facts,
            status,
            commands,
        })
    }

    /// Evaluate a resource's `when` condition. Returns:
    /// Some(true)  -> proceed
    /// Some(false) -> skipped_by_condition
    /// None        -> Unknown
    pub(crate) fn eval_condition(
        &self,
        res: &FrozenResource,
        item: Option<&EvalVal>,
    ) -> Result<Option<bool>> {
        let scope = self.scope(item, None, None);
        match &res.when {
            None => Ok(Some(true)),
            Some(w) => {
                let expr = parse_expr(w).map_err(|e| {
                    SinterError::plan(format!("{}: invalid when expression: {}", res.id, e))
                })?;
                match eval_boolean(&expr, &scope) {
                    Ok(v) => match v.val {
                        None => Ok(None),
                        Some(Value::Bool(b)) => Ok(Some(b)),
                        Some(_) => Err(SinterError::plan(format!(
                            "{}: when did not produce a boolean",
                            res.id
                        ))),
                    },
                    Err(e) => Err(SinterError::plan(format!(
                        "{}: when evaluation error: {}",
                        res.id, e
                    ))),
                }
            }
        }
    }

    /// Dispatch a resource whose condition is true. The condition must already
    /// have been evaluated by the caller.
    pub(crate) fn dispatch_resource(
        &mut self,
        res: &FrozenResource,
        item: Option<&EvalVal>,
    ) -> Result<ResourceResult> {
        let outcome = match res.type_.as_str() {
            "file" => self.run_file(res, item),
            "directory" => self.run_directory(res, item),
            "link" => self.run_link(res, item),
            "template" => self.run_template(res, item),
            "command" => self.run_command(res, item),
            "package" => self.run_package(res, item),
            "service" => self.run_service(res, item),
            other => Err(SinterError::schema(format!(
                "{}: unknown resource type {}",
                res.id, other
            ))),
        };
        match outcome {
            Ok(r) => Ok(r),
            Err(e) if e.kind == crate::error::ErrorKind::Unknown => {
                if self.opts.mode == Mode::Plan {
                    let mut r = unknown_result(res);
                    r.reason = Some(e.message);
                    Ok(r)
                } else {
                    Err(SinterError::apply(format!(
                        "{}: a required runtime value is Unknown during apply: {}",
                        res.id, e.message
                    )))
                }
            }
            Err(e) => Err(e),
        }
    }

    pub(crate) fn scope<'a>(
        &'a self,
        item: Option<&'a EvalVal>,
        result: Option<&'a BTreeMap<String, EvalVal>>,
        template: Option<&'a BTreeMap<String, EvalVal>>,
    ) -> Scope<'a> {
        Scope {
            vars: Some(&self.vars),
            facts: Some(&self.facts),
            registers: Some(&self.registers),
            item,
            result,
            template,
        }
    }

    pub(crate) fn eval_with<'a>(
        &'a self,
        res: &FrozenResource,
        item: Option<&'a EvalVal>,
    ) -> Result<BTreeMap<String, EvalVal>> {
        let scope = self.scope(item, None, None);
        let mut out = BTreeMap::new();
        for (k, v) in &res.with {
            let ev = eval_value_interpolated(v, &scope).map_err(|e| {
                SinterError::apply(format!("{}: cannot evaluate with.{}: {}", res.id, k, e))
            })?;
            out.insert(k.clone(), ev);
        }
        Ok(out)
    }

    fn run_handler(&mut self, h: &crate::model::FrozenHandler) -> Result<HandlerResult> {
        let action = match h.action {
            crate::ir::HandlerAction::Restart => "restart",
            crate::ir::HandlerAction::Reload => "reload",
        };
        let outcome = self.handler_service(h, action)?;
        let reason = match outcome {
            HandlerOutcomeState::Failed => Some(format!(
                "handler {} for service {} {}",
                h.id, h.service, "failed"
            )),
            HandlerOutcomeState::Indeterminate => Some(format!(
                "handler {} for service {} became indeterminate",
                h.id, h.service
            )),
            _ => None,
        };
        Ok(HandlerResult {
            id: h.id.clone(),
            service: h.service.clone(),
            action: action.to_string(),
            state: outcome,
            reason,
            sensitive: h.sensitive,
        })
    }
}

pub(crate) fn blocked_fail_fast(res: &FrozenResource) -> ResourceResult {
    ResourceResult {
        id: res.id.clone(),
        type_: res.type_.clone(),
        origin: res.origin.clone(),
        execution: Execution::NotRun,
        change: Change::None,
        verification: Verification::NotPerformed,
        disposition: Disposition::BlockedByFailFast,
        reason: None,
        unknown: false,
        sensitive: res.sensitive,
        diff: None,
        notes: Vec::new(),
        handler_notifications: Vec::new(),
        loop_index: res.loop_index,
    }
}

pub(crate) fn blocked_by_dependency(res: &FrozenResource, reason: &str) -> ResourceResult {
    ResourceResult {
        id: res.id.clone(),
        type_: res.type_.clone(),
        origin: res.origin.clone(),
        execution: Execution::NotRun,
        change: Change::None,
        verification: Verification::NotPerformed,
        disposition: Disposition::BlockedByDependency,
        reason: Some(reason.to_string()),
        unknown: false,
        sensitive: res.sensitive,
        diff: None,
        notes: Vec::new(),
        handler_notifications: Vec::new(),
        loop_index: res.loop_index,
    }
}

pub(crate) fn unknown_result(res: &FrozenResource) -> ResourceResult {
    ResourceResult {
        id: res.id.clone(),
        type_: res.type_.clone(),
        origin: res.origin.clone(),
        execution: Execution::NotRun,
        change: Change::None,
        verification: Verification::NotPerformed,
        disposition: Disposition::Normal,
        reason: None,
        unknown: true,
        sensitive: res.sensitive,
        diff: None,
        notes: Vec::new(),
        handler_notifications: Vec::new(),
        loop_index: res.loop_index,
    }
}

fn build_executor(opts: &RunOptions) -> Result<Executor> {
    match &opts.target.ssh {
        None => Ok(Executor::Local(LocalExecutor::new(opts.sudo)?)),
        Some(s) => {
            let cfg = SshConfig {
                host: s.host.clone(),
                port: s.port,
                user: s.user.clone(),
                known_hosts: s.known_hosts.clone(),
                identity_files: s.identity_files.clone(),
            };
            Ok(Executor::Ssh(SshExecutor::connect(&cfg, opts.sudo)?))
        }
    }
}

/// Connect and do a trivial capability probe before we build TargetFs.
fn connect_and_prepare(mut ex: Executor, _sudo: bool) -> Result<Executor> {
    // argv-only probe: no shell is involved and no recipe data is present.
    let mut req = ExecRequest::new("/usr/bin/test");
    req.args = vec!["-r".to_string(), "/etc/os-release".to_string()];
    let home = match &ex {
        Executor::Local(l) => l.home.clone(),
        Executor::Ssh(s) => s.home.clone(),
    };
    req.env = crate::resources::baseline_env(home);
    let out = ex.run(&req)?;
    if !out.is_success() {
        return Err(SinterError::connect(format!(
            "target does not appear to be a supported Linux system (/etc/os-release unreadable; exit={:?}, stderr={})",
            out.exit_code(),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(ex)
}

fn gather_target_info(ex: &mut Executor, sudo: bool) -> Result<(Facts, u32, u32, String)> {
    let hostname = run_text(ex, "/bin/hostname", &[])?;
    let os_release = run_text(ex, "/bin/cat", &["/etc/os-release"])?;
    let arch_raw = run_text(ex, "/usr/bin/uname", &["-m"])?;
    let arch = crate::facts::normalize_arch(&arch_raw);
    let facts = Facts::from_observed(hostname.trim().to_string(), &os_release, arch)?;
    let (uid, gid, home) = ex.target_identity()?;
    let _ = sudo;
    Ok((facts, uid, gid, home))
}

fn run_text(ex: &mut Executor, program: &str, args: &[&str]) -> Result<String> {
    let mut req = ExecRequest::new(program);
    req.args = args.iter().map(|s| s.to_string()).collect();
    let out = ex.run(&req)?;
    match out.completion {
        Completion::Exited(0) => Ok(String::from_utf8_lossy(&out.stdout).to_string()),
        _ => Err(SinterError::connect(format!(
            "target command {} failed during capability/fact collection",
            program
        ))),
    }
}

/// Deterministic execution order: dependencies first, ties broken by
/// declaration order (Kahn's algorithm with a min-heap on declaration index).
fn execution_order(model: &Model) -> Result<Vec<usize>> {
    let index: BTreeMap<&str, usize> = model
        .resources
        .iter()
        .enumerate()
        .map(|(i, r)| (r.id.as_str(), i))
        .collect();
    let n = model.resources.len();
    let mut indegree = vec![0usize; n];
    let mut dependents: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (i, r) in model.resources.iter().enumerate() {
        let mut seen = BTreeSet::new();
        for d in &r.depends_on {
            let di = *index.get(d.as_str()).ok_or_else(|| {
                SinterError::schema(format!("{}: unknown dependency {}", r.id, d))
            })?;
            if seen.insert(di) {
                indegree[i] += 1;
                dependents[di].push(i);
            }
        }
    }
    let mut ready: Vec<usize> = (0..n).filter(|i| indegree[*i] == 0).collect();
    ready.sort();
    let mut order = Vec::with_capacity(n);
    while let Some(&i) = ready.first() {
        ready.remove(0);
        order.push(i);
        for &d in &dependents[i] {
            indegree[d] -= 1;
            if indegree[d] == 0 {
                ready.push(d);
            }
        }
        ready.sort();
    }
    if order.len() != n {
        return Err(SinterError::schema("dependency graph contains a cycle"));
    }
    Ok(order)
}

// Allow targetfs construction with a pre-probed capability flag.
fn command_present(ex: &mut Executor, path: &str) -> Result<bool> {
    let mut req = ExecRequest::new("/usr/bin/test");
    req.args = vec!["-x".to_string(), path.to_string()];
    req.env = crate::resources::baseline_env(match ex {
        Executor::Local(l) => l.home.clone(),
        Executor::Ssh(s) => s.home.clone(),
    });
    match ex.run(&req)?.completion {
        Completion::Exited(0) => Ok(true),
        Completion::Exited(_) => Ok(false),
        _ => Err(SinterError::connect(
            "could not determine target command availability",
        )),
    }
}

/// Build a truthful failure/indeterminate result for a resource-level error.
fn failed_result_from_error(res: &FrozenResource, e: &SinterError) -> ResourceResult {
    let indeterminate = e.kind == crate::error::ErrorKind::Indeterminate;
    ResourceResult {
        id: res.id.clone(),
        type_: res.type_.clone(),
        origin: res.origin.clone(),
        execution: if indeterminate {
            Execution::Indeterminate
        } else {
            Execution::Failed
        },
        change: match e.mutation {
            MutationState::None => {
                if indeterminate {
                    Change::Possible
                } else {
                    Change::None
                }
            }
            MutationState::Changed => Change::Changed,
            MutationState::Possible => Change::Possible,
        },
        verification: if indeterminate {
            Verification::Unknown
        } else {
            Verification::NotPerformed
        },
        disposition: Disposition::Normal,
        reason: Some(e.message.clone()),
        unknown: false,
        sensitive: res.sensitive || res.derived_sensitive,
        diff: None,
        notes: Vec::new(),
        handler_notifications: Vec::new(),
        loop_index: res.loop_index,
    }
}

/// Build a register result map for a command resource.
pub fn command_register_map(
    executed: bool,
    completion: Option<&Completion>,
    output: Option<&Output>,
    changed: Option<bool>,
    execution: &str,
) -> BTreeMap<String, Value> {
    let mut m = BTreeMap::new();
    m.insert("executed".to_string(), Value::Bool(executed));
    if !executed {
        m.insert("exit_code".to_string(), Value::Null);
        m.insert("stdout".to_string(), Value::Null);
        m.insert("stderr".to_string(), Value::Null);
        m.insert("stdout_complete".to_string(), Value::Bool(true));
        m.insert("stderr_complete".to_string(), Value::Bool(true));
        m.insert("changed".to_string(), Value::Bool(false));
        m.insert("execution".to_string(), Value::Str(execution.to_string()));
        return m;
    }
    let exit_code = completion.and_then(|c| match c {
        Completion::Exited(i) => Some(Value::Int(*i as i64)),
        _ => None,
    });
    m.insert("exit_code".to_string(), exit_code.unwrap_or(Value::Null));
    let (stdout, stdout_complete) = match output {
        Some(o) => {
            let usable = !o.stdout_truncated && std::str::from_utf8(&o.stdout).is_ok();
            (
                if usable {
                    Value::Str(String::from_utf8_lossy(&o.stdout).to_string())
                } else {
                    Value::Null
                },
                Value::Bool(usable),
            )
        }
        None => (Value::Null, Value::Bool(false)),
    };
    let (stderr, stderr_complete) = match output {
        Some(o) => {
            let usable = !o.stderr_truncated && std::str::from_utf8(&o.stderr).is_ok();
            (
                if usable {
                    Value::Str(String::from_utf8_lossy(&o.stderr).to_string())
                } else {
                    Value::Null
                },
                Value::Bool(usable),
            )
        }
        None => (Value::Null, Value::Bool(false)),
    };
    m.insert("stdout".to_string(), stdout);
    m.insert("stderr".to_string(), stderr);
    m.insert("stdout_complete".to_string(), stdout_complete);
    m.insert("stderr_complete".to_string(), stderr_complete);
    m.insert("changed".to_string(), changefield(changed));
    m.insert("execution".to_string(), Value::Str(execution.to_string()));
    m
}

fn changefield(c: Option<bool>) -> Value {
    match c {
        Some(b) => Value::Bool(b),
        None => Value::Null,
    }
}
