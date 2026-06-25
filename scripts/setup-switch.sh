#!/usr/bin/env bash
#
# Create (or sync) a project-local opam switch in ./_opam, installing the
# dependencies declared in this project's *.opam file(s).
#
# Usage:
#   ./scripts/setup-switch.sh                 # let opam pick a compiler
#   OCAML_COMPILER=5.3.0 ./scripts/setup-switch.sh   # pin a compiler
#
# Idempotent: re-run any time to pick up new dependencies. Once it finishes,
# activate the switch in your shell with:  eval $(opam env)

set -euo pipefail

# Run from the repository root regardless of where the script is invoked.
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$script_dir/.."

if ! command -v opam >/dev/null 2>&1; then
  echo "error: opam is not installed or not on PATH." >&2
  echo "       See https://opam.ocaml.org/doc/Install.html" >&2
  exit 1
fi

# Deps (including {with-test} ones like alcotest) come from the *.opam files in
# this directory; `opam ... .` reads them. We install deps only, not the package.
opam_args=(--deps-only --with-test --yes)

if [ -d _opam ]; then
  echo "==> Local switch ./_opam exists; syncing dependencies…"
  opam install . "${opam_args[@]}"
else
  echo "==> Creating local switch in ./_opam…"
  if [ -n "${OCAML_COMPILER:-}" ]; then
    opam switch create . "$OCAML_COMPILER" "${opam_args[@]}"
  else
    # No compiler pinned: opam resolves one from the opam-file constraints.
    opam switch create . "${opam_args[@]}"
  fi
fi

echo
echo "==> Done. Activate the switch with:"
echo "      eval \$(opam env)"
echo "    then build with:  dune build"
