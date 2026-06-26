#!/usr/bin/env bash
set -euo pipefail

# Validates that the project builds from a clean environment by creating an
# isolated git worktree and a fresh opam switch with the minimum declared OCaml
# compiler, then building and running the test suite. Exits 0 on success.
#
# Usage:
#   bash scripts/validate-build.sh [--keep] [--local] [--lower-bounds]
#                                  [--compiler X.Y.Z]
#
# --keep            Preserve the switch and worktree after the run (debugging).
# --local           Copy dune-project and osx-keychain.opam from the working
#                   tree into the worktree, so uncommitted changes are validated.
# --lower-bounds    After installing deps, downgrade each declared dependency to
#                   its lower-bound version before building and testing.
# --compiler X.Y.Z  Validate against this exact compiler instead of the declared
#                   floor (e.g. to test a specific point release).
#
# Note on arm64 hosts:
#   The declared floor is OCaml 4.14, which is also the lowest release with a
#   native Apple Silicon (arm64) backend — so the floor builds and validates
#   directly on this hardware. The arm64 guard below is a safety net: it only
#   triggers if the floor is ever lowered, or --compiler names a pre-4.14
#   release, neither of which can be built on arm64. Pass --compiler to override.

# Lowest OCaml release with a native arm64 macOS backend.
_ARM64_MIN="4.14.0"

_parse_ocaml_version() {
  # Collapse newlines first: dune's formatter may split (ocaml (>= "x")) across
  # lines.
  tr '\n' ' ' < "$1" \
    | sed -n 's/.*(ocaml[[:space:]]*(>=[[:space:]]*"\([^"]*\)").*/\1/p'
}

# Resolve a possibly-partial version ("4.08") to a concrete ocaml-base-compiler
# release ("4.08.0"), picking the lowest available patch. Concrete versions pass
# through unchanged.
_resolve_compiler() {
  local v="$1"
  if [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]]; then
    echo "$v"
    return
  fi
  # No `| head`: head closing the pipe early would SIGPIPE sort and trip
  # pipefail. Capture the sorted list and take the first line in bash.
  local sorted
  sorted="$(opam show ocaml-base-compiler --field=all-versions 2>/dev/null \
    | tr ' ' '\n' | grep -E "^${v//./\\.}\.[0-9]+$" | sort -V)"
  echo "${sorted%%$'\n'*}"
}

# Echo the lower of two dotted versions (so "$1 < $2" iff lower == "$1").
_lower_version() {
  local sorted
  sorted="$(printf '%s\n%s\n' "$1" "$2" | sort -V)"
  echo "${sorted%%$'\n'*}"
}

# Parse declared dependencies from dune-project: lines of "pkg version" for each
# (pkg (>= "version")) entry, skipping dune, ocaml, and :with-dev-setup packages.
_parse_deps() {
  sed -n '/(depends/,/^[[:space:]]*)/p' "$1" \
    | grep -v ':with-dev-setup' \
    | grep -E '^\s*\([a-z]' \
    | grep -E '\(>=' \
    | sed -n 's/^[[:space:]]*(\([a-z0-9_-]*\)[[:space:]].*(>=[[:space:]]*"\([^"]*\)").*/\1 \2/p' \
    | grep -v -E '^(dune|ocaml) '
}

_print_resolved_versions() {
  local dune_project="$1"
  echo ""
  echo "Resolved dependency versions:"
  while read -r pkg _constraint; do
    local installed
    installed="$(opam list --installed "$pkg" --columns=version -s 2>/dev/null || echo "not found")"
    printf "  %-20s %s\n" "$pkg" "$installed"
  done < <(_parse_deps "$dune_project")
  echo ""
}

_SWITCH_NAME=""
_WORKTREE_DIR=""

_cleanup() {
  opam switch remove "$_SWITCH_NAME" --yes 2>/dev/null || true
  git worktree remove "$_WORKTREE_DIR" --force 2>/dev/null || true
}

main() {
  local repo_root keep=false use_local=false lower_bounds=false compiler_override=""
  repo_root="$(git rev-parse --show-toplevel)"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --keep)         keep=true; shift ;;
      --local)        use_local=true; shift ;;
      --lower-bounds) lower_bounds=true; shift ;;
      --compiler)     compiler_override="${2:?--compiler needs a version}"; shift 2 ;;
      *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
  done

  local suffix
  suffix="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  _SWITCH_NAME="oxkc-validate-$suffix"
  _WORKTREE_DIR="$(mktemp -d)"

  if [[ "$keep" == false ]]; then
    trap '_cleanup' EXIT
  else
    echo "--keep: will preserve switch '$_SWITCH_NAME' and worktree '$_WORKTREE_DIR'"
  fi

  echo "Creating worktree at $_WORKTREE_DIR..."
  git -C "$repo_root" worktree add "$_WORKTREE_DIR" HEAD --detach --quiet

  local dune_project="$_WORKTREE_DIR/dune-project"

  if [[ "$use_local" == true ]]; then
    echo "Copying working tree metadata into worktree (--local)..."
    cp "$repo_root/dune-project" "$dune_project"
    cp "$repo_root/osx-keychain.opam" "$_WORKTREE_DIR/osx-keychain.opam"
  fi

  echo "Updating package index..."
  opam update --quiet

  # Decide which compiler to validate against.
  local compiler
  if [[ -n "$compiler_override" ]]; then
    compiler="$compiler_override"
    echo "Using --compiler override: $compiler"
  else
    local declared
    declared="$(_parse_ocaml_version "$dune_project")"
    if [[ -z "$declared" ]]; then
      echo "Error: could not parse OCaml lower bound from dune-project" >&2
      exit 1
    fi
    echo "Declared OCaml floor: $declared"

    # arm64 has no OCaml backend before 4.14, and opam won't even offer those
    # releases on this host — so decide the raise from the *declared* version,
    # before trying to resolve it to an installable package.
    if [[ "$(uname -m)" == "arm64" \
          && "$(_lower_version "$declared" "$_ARM64_MIN")" == "$declared" \
          && "$declared" != "$_ARM64_MIN" ]]; then
      echo "Note: $declared predates arm64 support; raising to $_ARM64_MIN for this host."
      echo "      (The $declared floor is validated by opam-repository CI on x86/Linux.)"
      compiler="$_ARM64_MIN"
    else
      compiler="$(_resolve_compiler "$declared")"
      if [[ -z "$compiler" ]]; then
        echo "Error: no ocaml-base-compiler release matches declared floor '$declared'" >&2
        exit 1
      fi
    fi
  fi

  echo "Creating switch '$_SWITCH_NAME' with ocaml-base-compiler.$compiler..."
  opam switch create "$_SWITCH_NAME" "ocaml-base-compiler.$compiler"
  eval "$(opam env --switch="$_SWITCH_NAME" --set-switch)"

  echo "Installing dependencies..."
  cd "$_WORKTREE_DIR"
  opam install . --deps-only --with-test --yes

  _print_resolved_versions "$dune_project"

  if [[ "$lower_bounds" == true ]]; then
    echo "=== Lower-bound testing ==="
    echo "Downgrading each declared dependency to its lower-bound version..."
    echo ""

    local install_args=()
    while read -r pkg lower; do
      # Oldest available version satisfying >= lower (all-versions is ascending).
      local all_versions oldest_match=""
      all_versions="$(opam show "$pkg" --field=all-versions 2>/dev/null)"
      for v in $all_versions; do
        local cmp
        cmp="$(opam admin compare-versions "$v" "$lower")"
        if [[ "$cmp" == *">"* || "$cmp" == *"="* ]]; then
          oldest_match="$v"
          break
        fi
      done

      if [[ -z "$oldest_match" ]]; then
        echo "  warning: no version of $pkg >= $lower found, skipping"
        continue
      fi

      local current
      current="$(opam list --installed "$pkg" --columns=version -s 2>/dev/null || echo "?")"
      if [[ "$current" == "$oldest_match" ]]; then
        printf "  %-20s %s (already at lower bound)\n" "$pkg" "$oldest_match"
      else
        printf "  %-20s %s -> %s\n" "$pkg" "$current" "$oldest_match"
        install_args+=("$pkg.$oldest_match")
      fi
    done < <(_parse_deps "$dune_project")

    echo ""
    if [[ ${#install_args[@]} -gt 0 ]]; then
      local failed=()
      for spec in "${install_args[@]}"; do
        echo "Installing $spec..."
        if ! opam install "$spec" --yes 2>&1; then
          echo "  FAILED: $spec is not installable in this switch"
          failed+=("$spec")
        fi
      done
      echo ""
      echo "Versions after downgrade:"
      _print_resolved_versions "$dune_project"
      if [[ ${#failed[@]} -gt 0 ]]; then
        echo "ERROR: could not install: ${failed[*]}"
        echo "These lower bounds are too low for the validation compiler."
        exit 1
      fi
    else
      echo "All dependencies already at their lower bounds (or none declared)."
    fi
  fi

  echo "Building..."
  dune build

  echo "Running tests..."
  dune runtest

  echo ""
  echo "Validation passed (compiler: $compiler)."
}

main "$@"
