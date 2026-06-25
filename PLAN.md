# Plan: `osx-keychain` — an OCaml/opam binding for macOS Keychain Services

## Motivation

Searching opam (`keychain`, `keyring`, `secret`, `credential`, `SecItem`,
`Security.framework`) turns up **nothing that wraps the macOS Keychain**. The
closest precedents are the `osx-*` family of thin C-API bindings
(`osx-cf`, `osx-secure-transport`, …) and the `cf` CoreFoundation bindings.
The CLI fallback (`/usr/bin/security`) is enough for plain password
store/fetch/delete but cannot reach the features that actually justify a
library:

- `SecAccessControl` (Touch ID / Face ID / device-passcode / user-presence gating)
- per-item accessibility classes (`kSecAttrAccessibleWhenUnlocked`, …)
- the data-protection keychain (`kSecUseDataProtectionKeychain`)
- iCloud sync (`kSecAttrSynchronizable`) and access groups
- rich queries, `SecItemUpdate`, persistent refs, structured results/`OSStatus`
- keeping secrets in `CFData` we control instead of passing them through
  argv / stdout / the process table

So the goal is a **native ctypes binding to Keychain Services**, packaged in
the `osx-` register as `osx-keychain`.

## Scope

**In scope (v1):** generic & internet passwords; add / copy / update / delete;
accessibility classes; data-protection keychain; structured `OSStatus` errors;
ergonomic typed API returning `(_, error) result`.

**Later:** `SecAccessControl` + biometric/`LAContext` gating; `kSecAttrSynchronizable`;
access groups; rich multi-attribute queries / `kSecMatchLimitAll`; keys & certs
(`kSecClassKey`, `kSecClassCertificate`), trust evaluation.

**Out of scope:** legacy file-based keychain management (create/unlock/lock files,
`SecKeychainRef` APIs) beyond what the modern item API needs; we target the
modern `SecItem*` interface.

## Technical approach

### Binding strategy
**Revised after the Phase 0 spike (see results below): hand-written C stubs +
OCaml `external`, not ctypes.** The `SecItem*` surface is small and stable, and
the work is CF-heavy (build `CFDictionary` queries, `CFRelease` discipline,
`const CFStringRef` keys). All of that is markedly simpler and more robust in C
than threading it through ctypes — and using the `kSec*` constants directly in
C removes the flagged "read `const CFStringRef` from OCaml" risk entirely.
**Relation to the `osx-*` family (corrected after reading their sources):**
there is no single "osx-* way" — the David Sheets libs (`osx-cf`, `osx-xattr`,
`osx-membership`) use **ctypes stub generation** (`lib_gen/*_bindings.ml` +
`Cstubs`), while `osx-secure-transport` uses **`ctypes-foreign`** (dynamic). Our
hand-written C stubs are a deliberate third approach. Justification specific to
this API: `Cstubs`' header detection only extracts *integer* constants and
struct offsets, but every `kSec*` key is a `CFStringRef` *pointer* global — so
ctypes would relocate the const-global problem, not remove it. We keep the
family's *layering* (thin binding + ~200-line typed layer) but not its binding
mechanism.

**Adopt from the family — runtime-lock discipline.** `osx-xattr`'s C util wraps
every blocking syscall in `caml_release_runtime_system()` /
`caml_acquire_runtime_system()`. `SecItem*` calls IPC to `securityd`, and
Phase 3 biometric prompts block for seconds on user interaction — without
releasing the runtime lock that freezes all other OCaml threads (and Lwt/Async
via threads). **Every `SecItem*` external wraps its call this way from Phase 1.**
(The Phase 0 spike omitted this; the real stubs must not.)

### CoreFoundation dependency
The `SecItem*` API traffics entirely in CF types (`CFDictionaryRef`, `CFDataRef`,
`CFStringRef`, `CFNumberRef`, `CFBooleanRef`). **Resolved by Phase 0: no CF
dependency.** With hand-written C stubs the CF manipulation lives in C against
the SDK headers, so we need neither `cf` nor a vendored CF shim. This drops a
dependency and the entire "expose CF types to OCaml" surface. (Revisit only if a
future feature needs CF objects to cross the FFI boundary — none in scope do.)

### The `extern const CFStringRef` globals — resolved
All the keys/values are exported as `const CFStringRef` **symbols**
(`kSecClass`, `kSecClassGenericPassword`, `kSecAttrService`, `kSecValueData`,
`kSecReturnData`, `kSecMatchLimit`, …), not functions. This was flagged as the
main risk for a ctypes binding. With the C-stub strategy it is a **non-issue**:
the constants are referenced directly in C against the SDK headers. Phase 0
confirmed `kSecClass`, `kSecClassGenericPassword`, `kSecAttrService`,
`kSecAttrAccount`, `kSecValueData`, `kSecReturnData`, and `kSecMatchLimit*` all
work this way.

### Layering
1. C stubs (`keychain_stubs.c`) — the four `SecItem*` operations plus
   `SecCopyErrorMessageString` (and later `SecAccessControlCreateWithFlags`),
   exposed as a handful of `external`s. Owns all `CFDictionary` construction,
   `kSec*` constants, and `CFRelease` discipline. Marshals OCaml strings/bytes
   ↔ `CFString`/`CFData` at the boundary; returns plain OCaml values
   (`OSStatus` as `int`, data as `string`, results as tuples/variants).
2. `Osx_keychain` (public, pure OCaml) — ergonomic, typed, `result`-returning
   API over the externals. Maps `OSStatus` → `error`/`Ok None`, implements
   upsert, validates inputs. No CF type ever crosses into OCaml.

### Public API sketch
```ocaml
module Osx_keychain : sig
  type error = { status : int; message : string }   (* wrapped OSStatus *)

  type accessible =
    | When_unlocked | After_first_unlock
    | When_unlocked_this_device_only
    | After_first_unlock_this_device_only
    | When_passcode_set_this_device_only

  module Generic_password : sig
    val set :
      ?accessible:accessible ->
      ?label:string ->
      service:string -> account:string -> string ->
      (unit, error) result            (* add-or-update (upsert) *)

    val get :
      service:string -> account:string ->
      (string option, error) result    (* None = not found, Error = real failure *)

    val delete :
      service:string -> account:string ->
      (unit, error) result
  end

  module Internet_password : sig
    (* same shape, plus server / protocol / port / path *)
  end
end
```

**Design rules:**
- "not found" (`errSecItemNotFound`) is `Ok None` / not an `Error` — it is an
  expected outcome, not a failure.
- `set` is an upsert: try `SecItemAdd`; on `errSecDuplicateItem` fall back to
  `SecItemUpdate`. Document the semantics.
- Secrets in: accept `string` (and a `bytes` overload later so callers can
  zero the buffer). Secrets out: return `string` for v1; revisit `bytes` +
  wipe helper once the API settles. Document that OCaml's GC means we cannot
  guarantee secret erasure — this is the one thing the CLI route also can't do.
- Every public function returns `result`; no exceptions across the boundary.

## Reference material (`reference/`)

Built against the SDK and Apple's docs, not recall — there are **381 `errSec*`
codes and 163 `kSec*` globals**, too many to work from memory.

- `errsec.tsv`, `ksec.tsv`, `access_control_flags.tsv` — fact-tables extracted
  from the on-disk SDK headers (names + values only; headers not vendored, for
  licensing). Double as the tag-table test guard.
- `keychain-notes.md` — distilled behavioral gotchas the headers don't state
  (data-protection keychain, the `errSecDuplicateItem` upsert dance,
  entitlements/`-34018`, accessibility classes, biometrics, sync, threading),
  with inline Apple-docs citations. **Consult before finalizing API defaults.**
- See `reference/README.md` for provenance and regeneration.

## Build & packaging

- **Package name:** `osx-keychain` (matches the `osx-*` convention).
- **dune-project** (dune lang ≥ 3.x), `(foreign_stubs (language c) …)` for the
  C stubs.
- Framework linking: for a `(library …)`, use
  `(c_library_flags (-framework Security -framework CoreFoundation))`. (The
  Phase 0 *executable* used `(link_flags (-cclib -framework -cclib Security …))`
  because `c_library_flags` is a library-only field — noted so we don't trip on
  it again.)
- **opam:** `available: [ os = "macos" ]`; depends on `dune` only, plus
  `alcotest` as a `{with-test}` dep. No `ctypes`, no `cf`, no `conf-*` — the
  frameworks ship with the OS and the SDK headers come from the Command Line
  Tools. (Test framework: **Alcotest**, chosen now rather than swapping in at
  Phase 2; run with `--compact` in the dune action to keep success terse.)
- Optional later split: `osx-keychain` (sync core) + `osx-keychain-lwt`
  (offload blocking biometric prompts to a thread, mirroring `cf-lwt`).
- Standard repo furniture: `LICENSE` (ISC/MIT to match the family), `README.md`,
  `CHANGES.md`, CI.

## Testing

- **Round-trip unit tests** under a dedicated throwaway service name
  (`com.osx-keychain.test.<uuid>`): set → get (assert equal) → update → get →
  delete → get (assert `Ok None`). Always clean up in a teardown.
- **Error-path tests:** get on a missing item ⇒ `Ok None`; delete missing ⇒
  defined behavior; corrupt/duplicate handling.
- **Binary-secret test:** store bytes with NULs / high bytes, assert exact
  round-trip (this is precisely where the CLI's hex-dump is fragile).
- **Tag-table guard:** assert every `kSec*` / `errSec*` name the code references
  exists in `reference/{ksec,errsec}.tsv`, so a mistyped constant fails loudly
  rather than silently writing to the wrong attribute.
- **CI:** GitHub Actions `macos-latest` runner, matrix over a couple of OCaml
  versions. Tests that touch the login keychain may need an unlocked keychain;
  prefer creating an isolated test keychain or using the data-protection
  keychain to avoid interactive unlock prompts in CI.
- **Manual-only:** biometric / `SecAccessControl` paths can't run unattended
  (no Touch ID in CI) — gate behind an env var and document a manual checklist.

## Phasing / milestones

- **Phase 0 — Spike & de-risk. ✅ DONE.**
  Working end-to-end spike in `spike/` (`keychain_stubs.c` + `spike.ml`).
  Findings:
  - (a) `Security.framework` + `CoreFoundation` link cleanly from dune.
  - (b) `kSec*` const globals work — used directly in C, risk eliminated.
  - (c) Full `SecItemAdd`/`SecItemUpdate`/`SecItemCopyMatching`/`SecItemDelete`
    round-trip passes, **binary-faithful** (verified with an embedded NUL +
    high bytes — exactly where the `security` CLI's hex-dump is fragile).
  - **No keychain-unlock prompt** appeared for programmatic access in an
    interactive session (relevant to CI design — see open Q2).
  - **Decision:** hand-written C stubs over ctypes; **no CF dependency**.
  All 7 spike assertions green via `dune exec ./spike/spike.exe`.

- **Phase 1 — Generic password MVP.**
  `Generic_password` set/get/delete (upsert semantics), accessibility classes,
  data-protection keychain flag, `error` type via `SecCopyErrorMessageString`,
  the layering above, unit tests + CI green.

- **Phase 2 — Internet passwords & richer queries.**
  `Internet_password` (server/protocol/port/path), return-attributes,
  `kSecMatchLimitAll` enumeration, explicit `update`.

- **Phase 3 — Access control & sync.**
  `SecAccessControlCreateWithFlags` (biometry / user-presence / passcode),
  optional `LAContext`, `kSecAttrSynchronizable`, access groups. Manual test
  checklist for biometric flows.

- **Phase 4 — Ergonomics & release.**
  `bytes` + wipe helpers, optional `osx-keychain-lwt`, docs/examples, then
  submit to `opam-repository`.

## Open questions

1. ~~`cf` coverage vs. vendoring~~ — **resolved (Phase 0): no CF dependency; CF
   manipulation lives in the C stubs.**
2. Isolated test keychain vs. data-protection keychain in CI to avoid unlock
   prompts. (Phase 0 saw no prompt interactively, but headless CI agents have no
   unlocked login keychain — still needs validating on a real runner.)
3. Whether to expose `SecItemUpdate` directly in v1 or keep it behind upsert only.
4. Minimum macOS deployment target (data-protection keychain availability, signing/entitlement needs for access groups & iCloud sync).
5. Secret-erasure story: how hard to try given OCaml's moving GC — document limits vs. add a `bytes`-based zeroing path.
