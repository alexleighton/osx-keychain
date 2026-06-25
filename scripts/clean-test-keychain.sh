#!/usr/bin/env bash
#
# Delete leftover osx-keychain integration-test items from the login keychain,
# using the `security` CLI.
#
# The integration suite already cleans up after itself (per-test deletes plus an
# at_exit sweep), so you normally never need this. It exists for the one case
# that backstop can't cover: a test process hard-killed (SIGKILL, crash, power
# loss) before at_exit could run, leaving orphaned items behind.
#
# It only ever matches the test-owned naming scheme created by
# test/test_integration.ml:
#   generic  service  com.osx-keychain.test.<pid>[.list]
#   internet server   test-<pid>.osx-keychain.invalid[.list]
# Both are test-only (`.invalid` is a reserved TLD; the prefix is ours), so this
# can never touch real keychain data.
#
# Usage:
#   ./scripts/clean-test-keychain.sh            # delete leftover test items
#   ./scripts/clean-test-keychain.sh --dry-run  # list what would be deleted

set -euo pipefail

dry_run=0
case "${1:-}" in
  --dry-run|-n) dry_run=1 ;;
  "") ;;
  *) echo "usage: $0 [--dry-run]" >&2; exit 2 ;;
esac

# Identifying attributes the tests use. `svce` is kSecAttrService (generic
# passwords); `srvr` is kSecAttrServer (internet passwords). We read attributes
# only (no -d), so dump-keychain does not prompt per item.
dump="$(security dump-keychain 2>/dev/null || true)"

# Extract the full attribute values matching our test-only patterns. [^"]* after
# the fixed prefix/suffix also captures the ".list" sub-name variants.
services="$(printf '%s\n' "$dump" \
  | sed -n 's/.*"svce"<blob>="\(com\.osx-keychain\.test\.[^"]*\)".*/\1/p' \
  | sort -u)"
servers="$(printf '%s\n' "$dump" \
  | sed -n 's/.*"srvr"<blob>="\(test-[0-9]*\.osx-keychain\.invalid[^"]*\)".*/\1/p' \
  | sort -u)"

deleted=0

# A service/server can hold several accounts; each delete removes one matching
# item, so loop until no match remains (exit status != 0).
for svc in $services; do
  if [ "$dry_run" -eq 1 ]; then
    echo "would delete generic-password item(s) with service: $svc"
    continue
  fi
  while security delete-generic-password -s "$svc" >/dev/null 2>&1; do
    deleted=$((deleted + 1))
  done
done

for srv in $servers; do
  if [ "$dry_run" -eq 1 ]; then
    echo "would delete internet-password item(s) with server: $srv"
    continue
  fi
  while security delete-internet-password -s "$srv" >/dev/null 2>&1; do
    deleted=$((deleted + 1))
  done
done

if [ "$dry_run" -eq 1 ]; then
  if [ -z "$services$servers" ]; then
    echo "No leftover integration-test items found."
  fi
else
  echo "Removed $deleted leftover integration-test item(s)."
fi
