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

- **Tag-table guard:** a test asserts every `kSec*` / `errSec*` name our code
  references exists in these tables, so a typo fails loudly.
- **Error mapping:** `errsec.tsv` drives which `OSStatus` codes get named error
  variants vs. fall through to a generic `{ status; message }`.

## Licensing note

These TSVs contain only **symbol names and their integer values** — facts
extracted from the system SDK headers, not the headers' copyrighted text. We do
**not** vendor Apple's header files. Regenerate with the extraction commands
recorded in the project history (they read the local Command Line Tools SDK via
`xcrun --show-sdk-path`).
