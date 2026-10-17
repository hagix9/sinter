#!/usr/bin/env bash
# Public-tree guard (S151-27, IGN-01..05): the root .gitignore must keep local
# work products (reports, evidence, scratch, nested clones, agent settings)
# out of the repository, must never ignore a file that belongs to the public
# tree, and no tracked file may match an ignore rule.
#
# Usage: .github/scripts/check-public-tree.sh   (from the repository root)
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
fail=0

# Paths that must stay publishable (never ignored).
must_publish=(
  README.md README.ja.md LICENSE-MIT LICENSE-APACHE SECURITY.md CHANGELOG.md
  DESIGN.md GOALS.md RELEASE.md install.sh Cargo.toml Cargo.lock .gitignore
  src/main.rs src/pgrole.rs tests/dnf_refusals.rs tests/fixtures/secrets/x.age
  docs/adr/0001-progress-output.md docs/adr/0002-future.md
  docs-site/src/content/docs/en/index.mdx docs-site/src/data/resources.json
  examples/start/hello.yaml examples/quick/README.md
  examples/recipes/postgresql-os.yaml examples/recipes/README.md
  .github/workflows/ci.yml .github/scripts/check-public-tree.sh
  .devcontainer/devcontainer.json .agents/skills/sinter/SKILL.md
  release/ACCEPTANCE_EVIDENCE.md release/check_acceptance_manifest.py
  release/evidence/v1.5.0/acceptance-manifest.json
  release/evidence/v1.5.1/acceptance-manifest.json
  release/acceptance-harness/README.md release/acceptance-harness/harness.env.example
  gateway/docs/PRODUCTION_DEPLOYMENT.md gateway/SINTER_GATEWAY_NEW.md
  submission/openai/SUBMISSION.md assets/demo/sinter-demo.svg
)
# Local work products that must be ignored.
must_ignore=(
  SINTER_NEW_REPORT_2026-10-17.md OPENSSF_FOLLOWUP.md WP_N_IMPLEMENTATION_REPORT.md
  POST_V1.5.1_NOTES.md V151_PLAN.md CODEX_LAST_RESULT.txt AGENTS.md CLAUDE.md
  .work/v1.5.1/report.md tmp/scratch.log work_review/a.md research/notes.md
  artifacts/out.tgz audit-handoff/x.md acceptance-harness-fix-2/run.sh
  v1.5.1-release-restart-2026-10-17/evidence.json docs/f3-dependency-evidence/a.log
  docs/next-improvements-2026-10-15/REPORT.md Sinter-Dev/README.md
  Sinter-Dev-FS0/src/main.rs worktrees/v1.5.1-phase3/README.md
  .opencode/commands/goal.md .claude/settings.local.json
  release/acceptance-harness/harness.env release/acceptance-harness/sanitize-patterns.tsv
)

# 0 = ignored, 1 = not ignored; anything else (a fatal git error) stops the
# check instead of being read as "not ignored".
ignored() {
  local rc=0
  git check-ignore -q --no-index -- "$1" || rc=$?
  case "$rc" in
    0|1) return "$rc" ;;
    *) echo "::error::git check-ignore failed (rc=$rc) for $1"; exit 2 ;;
  esac
}
for p in "${must_publish[@]}"; do
  if ignored "$p"; then
    echo "::error::public path is ignored: $p ($(git check-ignore -v --no-index -- "$p"))"
    fail=1
  fi
done
for p in "${must_ignore[@]}"; do
  if ! ignored "$p"; then
    echo "::error::local work product is not ignored: $p"
    fail=1
  fi
done
tracked_ignored=$(git ls-files -ci --exclude-standard)
if [ -n "$tracked_ignored" ]; then
  echo "::error::tracked files match an ignore rule:"; echo "$tracked_ignored"
  fail=1
fi
if [ "$fail" -ne 0 ]; then exit 1; fi
echo "public-tree guard: ${#must_publish[@]} publishable and ${#must_ignore[@]} local paths checked; no tracked file is ignored"
