#!/usr/bin/env bash
# Schema-validate every example recipe and every complete recipe in the docs
# (S151-11 / WEB-07) with the built binary — no target, no network, no secret.
#
#   .github/scripts/validate-examples.sh <path/to/sinter> [--self-test]
#
# * examples/**/*.yaml: every recipe and bundle (inventories are skipped:
#   a file with a top-level `hosts:` and no `resources:`/`recipes:`). New
#   files are picked up automatically.
# * docs-site/src/content/docs/**/*.md{,x}: every ```yaml block that is a
#   complete recipe — it starts with `version: 1` or has a top-level
#   `resources:` — is validated as written (so a sample missing `version` or a
#   field fails). Fragments, schema illustrations with `<placeholder>` tokens
#   and bundle examples (top-level `recipes:`, which name files that are not
#   in the docs) are skipped.
# * A `{ secret: <path> }` reference gets a placeholder copy of an existing
#   age fixture (tests/fixtures/secrets/go-recipient.age): validate checks
#   the reference and the age header only, never decrypts.
# * The copies live under /tmp (the hosted runner's /home carries a default
#   ACL that the controller-side trust check rightly refuses).
# --self-test also proves that an invalid recipe makes this script fail.
set -euo pipefail
SINTER=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
ROOT=$(git rev-parse --show-toplevel)
PLACEHOLDER="$ROOT/tests/fixtures/secrets/go-recipient.age"
WORK=$(mktemp -d /tmp/sinter-examples.XXXXXX)
trap 'rm -rf "$WORK"' EXIT
cp -R "$ROOT/examples" "$WORK/examples"
mkdir -p "$WORK/docs"

# Complete recipes from the docs.
python3 - "$ROOT/docs-site/src/content/docs" "$WORK/docs" <<'PY'
import os, re, sys
src, dst = sys.argv[1], sys.argv[2]
n = 0
for d, _, files in os.walk(src):
    for f in sorted(files):
        if not f.endswith((".md", ".mdx")):
            continue
        rel = os.path.relpath(os.path.join(d, f), src)
        text = open(os.path.join(d, f), encoding="utf-8").read()
        for i, block in enumerate(re.findall(r"```ya?ml[^\n]*\n(.*?)```", text, re.S)):
            first = next((l for l in block.splitlines() if l.strip() and not l.lstrip().startswith("#")), "")
            top = [l for l in block.splitlines() if l and not l[0].isspace() and not l.startswith("#")]
            is_recipe = first.strip() == "version: 1" or any(l.startswith("resources:") for l in top)
            is_bundle = any(l.startswith("recipes:") for l in top)
            # A schema illustration with <placeholder> tokens is not a sample.
            if not is_recipe or is_bundle or re.search(r"<[a-z_]+>", block):
                continue
            name = rel.replace(os.sep, "__").rsplit(".", 1)[0] + f"__{i}.yaml"
            open(os.path.join(dst, name), "w", encoding="utf-8").write(block)
            n += 1
print(f"docs: {n} complete recipe block(s) extracted")
PY
# Guard against a silent no-op (docs moved, fence syntax changed, ...).
MIN_DOCS=36
MIN_EXAMPLES=15
docs_n=$(find "$WORK/docs" -name '*.yaml' -type f | wc -l | tr -d ' ')
ex_n=$(find "$WORK/examples" -name '*.yaml' -type f | wc -l | tr -d ' ')
if [ "$docs_n" -lt "$MIN_DOCS" ] || [ "$ex_n" -lt "$MIN_EXAMPLES" ]; then
  echo "::error::too few recipes found (docs $docs_n < $MIN_DOCS or examples $ex_n < $MIN_EXAMPLES)"; exit 1
fi

# Template sources named by docs samples (relative to the recipe) get a
# placeholder; the examples ship their own.
while IFS= read -r f; do
  dir=$(dirname "$f")
  { grep -oE '^ *source: *[^ #]+' "$f" || true; } | sed -E 's/^ *source: *//' | while IFS= read -r ref; do
    case "$ref" in /*|*..*|*'{{'*) continue ;; esac
    mkdir -p "$dir/$(dirname "$ref")"
    [ -e "$dir/$ref" ] || printf 'placeholder\n' > "$dir/$ref"
  done
done < <(find "$WORK/docs" -name '*.yaml' -type f)

# Secret placeholders for every referenced path (relative to the recipe).
while IFS= read -r f; do
  dir=$(dirname "$f")
  { grep -oE 'secret: *[^ },]+' "$f" || true; } | sed -E 's/secret: *//' | while IFS= read -r ref; do
    case "$ref" in /*|*..*) continue ;; esac
    mkdir -p "$dir/$(dirname "$ref")"
    [ -e "$dir/$ref" ] || cp "$PLACEHOLDER" "$dir/$ref"
  done
done < <(find "$WORK" -name '*.yaml' -type f)

if [ "${2:-}" = --self-test ]; then
  printf 'version: 1\nresources:\n  - id: bad\n    type: file\n    with:\n      path: relative/path\n      no_such_field: 1\n' > "$WORK/examples/zz-self-test-invalid.yaml"
fi

checked=0; failed=0
while IFS= read -r f; do
  rel=${f#"$WORK"/}
  if grep -qE '^hosts:' "$f" && ! grep -qE '^(resources|recipes):' "$f"; then
    echo "skip (inventory): $rel"; continue
  fi
  if out=$("$SINTER" validate "$f" 2>&1); then
    checked=$((checked + 1))
  else
    failed=$((failed + 1)); echo "::error::$rel: $out"
  fi
done < <(find "$WORK/examples" "$WORK/docs" -name '*.yaml' -type f | sort)

echo "validated $checked recipe(s); $failed failed"
if [ "${2:-}" = --self-test ]; then
  if [ "$failed" -eq 1 ]; then echo "self-test: the invalid recipe was rejected"; exit 0; fi
  echo "::error::self-test: expected exactly one failure, got $failed"; exit 1
fi
[ "$failed" -eq 0 ]
