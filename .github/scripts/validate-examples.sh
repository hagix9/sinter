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
# * A file that another example includes is a fragment: it is validated as part
#   of the recipe that includes it, not on its own. An included file that git
#   ignores (local secrets) is supplied, in the copy only, from a committed
#   synthetic sample beside its directory (`X/file.yaml` <- `X.example/file.yaml`).
# * A file this script itself creates as a `source:` placeholder is not a
#   recipe: it is recorded and never validated on its own (it exists only so
#   that the recipe naming it passes the source check).
# --self-test also proves, against synthetic inputs, that an invalid example, a
# docs recipe without `version`, and an example with a missing source each make
# this script fail, and that a handler fragment, a `<placeholder>` sample and a
# generated source placeholder do not.
set -euo pipefail
SINTER=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
ROOT=$(git rev-parse --show-toplevel)
PLACEHOLDER="$ROOT/tests/fixtures/secrets/go-recipient.age"
WORK=$(mktemp -d /tmp/sinter-examples.XXXXXX)
trap 'rm -rf "$WORK"' EXIT
cp -R "$ROOT/examples" "$WORK/examples"
mkdir -p "$WORK/docs"

# Complete recipes from the docs (and, in --self-test, from synthetic pages).
extract_docs() {
python3 - "$1" "$WORK/docs" <<'PY'
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
}
extract_docs "$ROOT/docs-site/src/content/docs"
# Guard against a silent no-op (docs moved, fence syntax changed, ...).
MIN_DOCS=36
MIN_EXAMPLES=15
docs_n=$(find "$WORK/docs" -name '*.yaml' -type f | wc -l | tr -d ' ')
ex_n=$(find "$WORK/examples" -name '*.yaml' -type f | wc -l | tr -d ' ')
if [ "$docs_n" -lt "$MIN_DOCS" ] || [ "$ex_n" -lt "$MIN_EXAMPLES" ]; then
  echo "::error::too few recipes found (docs $docs_n < $MIN_DOCS or examples $ex_n < $MIN_EXAMPLES)"; exit 1
fi

# --self-test inputs. Synthetic only; they are added after the floors above, so
# the floors apply to the real docs and examples. The docs page holds, in this
# order: [0] a valid complete recipe whose `source:` names a .yaml file (a
# generated placeholder must not be validated as a recipe), [1] a complete
# recipe without `version` (must fail), [2] a handlers-only fragment and [3] a
# sample with a <placeholder> token (neither is a complete recipe: not
# extracted).
if [ "${2:-}" = --self-test ]; then
  mkdir -p "$WORK/selftest-docs"
  cat > "$WORK/selftest-docs/zz-self-test.md" <<'MD'
```yaml
version: 1
resources:
  - id: st_ok
    type: file
    with:
      path: /etc/zz-self-test.conf
      source: files/zz-self-test-source.yaml
```

```yaml
resources:
  - id: st_no_version
    type: file
    with:
      path: /etc/zz-self-test.conf
      content: x
```

```yaml
handlers:
  - id: st_fragment
    type: ca_trust
```

```yaml
version: 1
resources:
  - id: st_placeholder
    type: file
    with:
      path: /etc/<name>.conf
      content: x
```
MD
  extract_docs "$WORK/selftest-docs"
  [ "$(find "$WORK/docs" -name 'zz-self-test__*.yaml' | wc -l | tr -d ' ')" = 2 ] \
    || { echo "::error::self-test: expected exactly 2 synthetic docs recipes to be extracted"; exit 1; }
  printf 'version: 1\nresources:\n  - id: bad\n    type: file\n    with:\n      path: relative/path\n      no_such_field: 1\n' > "$WORK/examples/zz-self-test-invalid.yaml"
  printf 'version: 1\nresources:\n  - id: bad_source\n    type: file\n    with:\n      path: /etc/zz-self-test.conf\n      source: ""\n' > "$WORK/examples/zz-self-test-empty-source.yaml"
fi

# Template sources named by docs samples (relative to the recipe) get a
# placeholder; the examples ship their own. A placeholder this loop creates is
# recorded: it is a stand-in file, not a recipe, and is never validated.
PLACEHOLDERS="$WORK/placeholders.txt"
: > "$PLACEHOLDERS"
while IFS= read -r f; do
  dir=$(dirname "$f")
  { grep -oE '^ *source: *[^ #]+' "$f" || true; } | sed -E 's/^ *source: *//' | while IFS= read -r ref; do
    case "$ref" in /*|*..*|*'{{'*) continue ;; esac
    mkdir -p "$dir/$(dirname "$ref")"
    if [ ! -e "$dir/$ref" ]; then
      printf 'placeholder\n' > "$dir/$ref"
      echo "${dir#"$WORK"/}/$ref" >> "$PLACEHOLDERS"
    fi
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

# Files another example includes are fragments: they are validated as part of
# the recipe that includes them, not on their own. An included file that git
# ignores (local secrets the operator generates) is supplied, in the copy only,
# from the committed synthetic sample beside its directory:
# `<dir>/X/file.yaml` <- `<dir>/X.example/file.yaml`. Without a sample the
# include stays missing and validation fails, as it should.
FRAGMENTS="$WORK/fragments.txt"
python3 - "$WORK" "$ROOT" "$FRAGMENTS" <<'PY'
import os, re, shutil, subprocess, sys
work, root, out = sys.argv[1], sys.argv[2], sys.argv[3]
frags = set()
for d, _, files in os.walk(os.path.join(work, "examples")):
    for f in sorted(files):
        if not f.endswith((".yaml", ".yml")):
            continue
        lines = open(os.path.join(d, f), encoding="utf-8").read().splitlines()
        inc = False
        for line in lines:
            if re.match(r"^include:\s*$", line):
                inc = True
                continue
            if inc and line and not line[0].isspace() and not line.startswith("#"):
                inc = False
            m = re.match(r"^\s+-\s+([^\s#]+)", line) if inc else None
            if not m:
                continue
            ref = m.group(1).strip("'\"")
            if ref.startswith("/") or ".." in ref.split("/"):
                continue
            target = os.path.normpath(os.path.join(d, ref))
            frags.add(os.path.relpath(target, work))
            if os.path.exists(target) or "/" not in ref:
                continue
            original = os.path.join(root, os.path.relpath(target, work))
            ignored = subprocess.run(["git", "-C", root, "check-ignore", "-q", original]).returncode == 0
            head, rest = ref.split("/", 1)
            sample = os.path.join(d, head + ".example", rest)
            if ignored and os.path.isfile(sample):
                os.makedirs(os.path.dirname(target), exist_ok=True)
                shutil.copyfile(sample, target)
                print(f"sample for ignored include: {os.path.relpath(target, work)}")
open(out, "w").write("".join(f + "\n" for f in sorted(frags)))
PY

checked=0; failed=0; skipped_ph=0; failed_list=""
while IFS= read -r f; do
  rel=${f#"$WORK"/}
  if grep -qxF "$rel" "$PLACEHOLDERS"; then
    skipped_ph=$((skipped_ph + 1)); echo "skip (generated source placeholder): $rel"; continue
  fi
  if grep -qE '^hosts:' "$f" && ! grep -qE '^(resources|recipes):' "$f"; then
    echo "skip (inventory): $rel"; continue
  fi
  if grep -qxF "$rel" "$FRAGMENTS"; then
    echo "skip (included by another example): $rel"; continue
  fi
  if out=$("$SINTER" validate "$f" 2>&1); then
    checked=$((checked + 1))
  else
    failed=$((failed + 1)); failed_list="$failed_list$rel"$'\n'; echo "::error::$rel: $out"
  fi
done < <(find "$WORK/examples" "$WORK/docs" -name '*.yaml' -type f | sort)

echo "validated $checked recipe(s); $failed failed; $skipped_ph generated placeholder(s) not validated"
if [ "${2:-}" = --self-test ]; then
  # Exactly these, no more and no less: a broken extraction or a missing
  # rejection must not hide behind a matching count.
  expected=$'docs/zz-self-test__1.yaml\nexamples/zz-self-test-empty-source.yaml\nexamples/zz-self-test-invalid.yaml'
  if [ "$(printf '%s' "$failed_list" | sort)" = "$expected" ]; then
    echo "self-test: the 3 invalid synthetic recipes were rejected; the valid, fragment and placeholder inputs were not"; exit 0
  fi
  echo "::error::self-test: expected exactly the failures [$(echo "$expected" | tr '\n' ' ')], got [$(printf '%s' "$failed_list" | tr '\n' ' ')]"; exit 1
fi
# The floor counts what was validated, not what was found: a script that
# silently skips (or fails to reach) most of the recipes must not pass.
MIN_VALIDATED=55
if [ "$checked" -lt "$MIN_VALIDATED" ]; then
  echo "::error::too few recipes validated ($checked < $MIN_VALIDATED)"; exit 1
fi
[ "$failed" -eq 0 ]
