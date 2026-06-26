# Reference material

Source-of-truth data for the `osx-keychain` binding, so the implementation is
built against the SDK and Apple's docs rather than anyone's memory.

## Files

| File | What | Provenance |
|---|---|---|
| `errsec.tsv` | All `errSec*` result codes (`name`, `value`, `description`) — 381 codes | Extracted from `Security.framework/Headers/SecBase.h` |
| `ksec.tsv` | All `kSec*` `CFStringRef` keys/values (`name`, `group`) — 163 globals | Extracted from `…/SecItem.h` |
| `access_control_flags.tsv` | `SecAccessControlCreateFlags` (`name`, `value`, `deprecated`, `macos_since`) | Extracted from `…/SecAccessControl.h` |
| `keychain-notes.md` | Behavioral gotchas the headers don't state (data-protection keychain, upsert dance, entitlements/`-34018`, accessibility, biometrics, sync, threading) | Distilled from Apple docs with inline citations |

## How the TSVs are used

Two unit guards (`test/test_unit.ml`) check the code against these tables, so a
typo or transposed value fails at `dune runtest` rather than at link time or in
production:

- **`errsec.tsv` — value guard.** The `OSStatus` codes `code_of_status` branches
  on are verified by *name* against the SDK-extracted values, catching a
  transposed number. The table is the source of truth for that hand-written map
  (which codes get named variants vs. fall through to a generic
  `{ status; message }`); the guard keeps the two in sync.
- **`ksec.tsv` — name guard.** Every `kSec*` key referenced in
  `keychain_stubs.c` is asserted to exist in the table. A mistyped key would
  otherwise be accepted by the C compiler as an implicit extern and only surface
  at link or runtime.

`access_control_flags.tsv` and `keychain-notes.md` are reference-only (not yet
exercised by a test).

## Licensing note

These TSVs contain only **symbol names and their integer values** — facts
extracted from the system SDK headers, not the headers' copyrighted text. We do
**not** vendor Apple's header files. To regenerate, re-extract these symbols from
the SDK headers named in the table above (located via `xcrun --show-sdk-path`).
