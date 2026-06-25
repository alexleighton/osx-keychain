# Plan: `osx-keychain` — an OCaml/opam binding for macOS Keychain Services

## Motivation

Searching opam (`keychain`, `keyring`, `secret`, `credential`, `SecItem`,
`Security.framework`) turns up **nothing that wraps the macOS Keychain**. The
closest precedents are the `osx-*` family of thin C-API bindings
(`osx-cf`, `osx-secure-transport`, …) and the `cf` CoreFoundation bindings.

The realistic alternative today is shelling out to `/usr/bin/security`. That
works (it's how most programs read a stored credential — an API token, app password, etc.), but it's clumsy
in ways a native binding fixes **without any code-signing or entitlements**:

- **Structured results.** Real `OSStatus` codes and a typed `result`, instead of
  parsing CLI text + exit codes. "Not found" is `Ok None`, not a string match.
- **Binary fidelity.** Secrets round-trip exactly, including embedded NULs and
  high bytes — precisely where the CLI's `0x…` hex-dump is fragile.
- **No subprocess.** No process spawn per operation; secrets don't pass through
  argv / stdout / the process table / shell history.
- **Typed, mistake-resistant API** over the same `SecItem*` calls the CLI makes.

So the goal is a **hand-written C-stub binding to the modern `SecItem*` API**,
packaged in the `osx-` register as `osx-keychain`. (The richer Keychain features
— biometrics, the data-protection keychain, iCloud sync — are real, but they all
require Apple Developer provisioning to use *and* to test; they are deliberately
out of v1. See Scope.)

## Scope

**The scope line is drawn at "what an unsigned binary can do *and we can test*."**
A Phase 0.5 probe (`spike/dp_probe.*`) established this empirically on a stock
machine:

| Signing | File-based keychain | Data-protection keychain |
|---|---|---|
| Unsigned / ad-hoc | ✅ works | ❌ `errSecMissingEntitlement` (-34018) |
| Ad-hoc + `keychain-access-groups` entitlement | — | 💀 **kernel-killed at launch** |

`keychain-access-groups` is a *restricted* entitlement: macOS only honors it via
a provisioning profile, which requires a paid Apple Developer **Team ID**. So the
entire data-protection keychain — and everything built on it (biometrics, sync,
access groups) — is gated behind a Developer membership + signing both to *use*
and to *test*. Neither our CI nor a typical contributor (nor a typical user of
this library) has that, and we won't ask them to.

**In scope (v1) — file-based keychain, fully testable unsigned:**
- generic & internet passwords; add / copy / update (upsert) / delete;
- structured `OSStatus` → typed errors; `(_, error) result` API;
- exact binary round-trip; ACL / trusted-app prompt handling.

**Deferred — experimental, provisioning-gated, NOT verified in CI:**
- the `Data_protection` backend (kept as a `backend` parameter + code path, but
  documented "requires a provisioning profile; unverified"); `kSecAttrAccessible`
  classes; `kSecAttrSynchronizable` / iCloud; access groups. We won't build
  `SecAccessControl` / biometric / `LAContext` gating until there's a concrete
  signed-app consumer **and** a way to test it (Touch ID hardware + a human).
- This isn't a one-way door: file-based and DP share the *same* `SecItem*` API,
  so enabling DP later is a default/flag change, not a redesign (see "default
  backend" below). The file-based store is reached via non-deprecated `SecItem*`
  API and has no announced removal date, so v1 is not built on sand.

**Out of scope:** the legacy `SecKeychain*` management API (create/unlock/lock
files) — deprecated since ~macOS 12; we use only the modern `SecItem*` interface.
Keys & certs (`kSecClassKey`, `kSecClassCertificate`), trust evaluation.

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

  (* Which keychain to target — see the data-protection decision below. *)
  type backend = File_based | Data_protection

  (* Tri-state, because a query that omits synchronizable silently matches
     only non-synchronizable items (notes §6). *)
  type sync = No | Yes | Any

  module Generic_password : sig
    val set :
      ?backend:backend ->          (* default: File_based — see decision *)
      ?accessible:accessible ->    (* default: When_unlocked *)
      ?synchronizable:sync ->      (* default: No *)
      ?label:string ->
      service:string -> account:string -> string ->
      (unit, error) result            (* add-or-update (upsert) *)

    val get :
      ?backend:backend -> ?synchronizable:sync ->
      service:string -> account:string ->
      (string option, error) result    (* None = not found, Error = real failure *)

    val delete :
      ?backend:backend -> ?synchronizable:sync ->   (* Any is often right here *)
      service:string -> account:string ->
      (unit, error) result
  end

  module Internet_password : sig
    (* same shape, plus server / protocol / port / path *)
  end
end
```

**Design rules:**
- "not found" (`errSecItemNotFound`, -25300) is `Ok None` / not an `Error` — it
  is an expected outcome, not a failure.
- `set` is an upsert: try `SecItemAdd`; on `errSecDuplicateItem` (-25299) fall
  back to `SecItemUpdate`. **Three separate dicts** (notes §2): the match query
  (full primary key, no value/return keys), the attrs-to-update (`kSecValueData`
  only), and the add dict — never reuse one mutable dict across calls.
- **Always include `kSecMatchLimit` and the full primary key on delete.** In the
  data-protection keychain a limit-less delete removes *all* matches, and in the
  file-based keychain an under-specified query can hit *other apps'/the system's*
  items ("very dangerous", notes §1). We construct queries; we own this safety.
- Map a named-error set off `errsec.tsv`: `Not_found`, `Duplicate`, `Auth_failed`,
  `User_canceled` (distinct from auth failure!), `Interaction_not_allowed`,
  `Missing_entitlement`, `Param` — everything else falls through to
  `{ status; message }`. **Never** treat `errSecInteractionNotAllowed` (-25308)
  as "delete and recreate" (notes §4) — it means "locked / not readable now".
- Secrets in: accept `string` (and a `bytes` overload later so callers can
  zero the buffer). Secrets out: return `string` for v1; revisit `bytes` +
  wipe helper once the API settles. Document that OCaml's GC means we cannot
  guarantee secret erasure — this is the one thing the CLI route also can't do.
- Every public function returns `result`; no exceptions across the boundary.

**Decided: default `File_based`, `Data_protection` is explicit opt-in.**
(Confirmed empirically — programs routinely read a stored credential like an
API token from the file-based keychain via `security find-generic-password` on an unsigned
process; our default mode is a drop-in for exactly that.) The research
(notes §1, §3) surfaced the underlying tension:
- The data-protection keychain is the modern, non-deprecated, feature-rich path
  (biometrics, accessibility, sync) and walls our deletes off from the shared
  system keychain — *but it requires code-signing entitlements*. An unsigned
  binary (which is what `dune exec`, most OCaml CLIs/daemons, and CI runners are)
  hitting it fails with `errSecMissingEntitlement` (-34018).
- The file-based keychain works unsigned with no entitlements, but is on the road
  to deprecation and can't do biometrics/sync.

Rationale: a library whose default mode fails out-of-the-box for most of its
likely callers (unsigned tools) is a bad default; users who need the DP-only
features are already in signed-app-bundle territory and can opt in. (This
*diverges* from the notes' "default to DP" recommendation, which is written for
app developers, not a general-purpose library.) Tests default to `File_based`
for green CI, with a separate signed/manual lane exercising `Data_protection`.

Note for the file-based path: its access control is **ACL + trusted-apps**, not
entitlements — a *different* binary reading an item another app created can
trigger a one-time GUI "allow" prompt (this is why the `security` CLI is silent
but our binary might prompt on first read of a `security`-created item). Manage
via the trusted-app list on `SecItemCopyMatching`; relevant when we swap such a
`security`-CLI subprocess call for this library.

## Reference material (`reference/`)

Built against the SDK and Apple's docs, not recall — there are **381 `errSec*`
codes and 163 `kSec*` globals**, too many to work from memory.

- `errsec.tsv`, `ksec.tsv`, `access_control_flags.tsv` — fact-tables extracted
  from the on-disk SDK headers (names + values only; headers not vendored, for
  licensing). Double as the tag-table test guard.
- `keychain-notes.md` — distilled behavioral gotchas the headers don't state
  (data-protection keychain, the `errSecDuplicateItem` upsert dance,
  entitlements/`-34018`, accessibility classes, biometrics, sync, threading),
  with inline Apple-docs citations (primarily Apple DTS engineer Quinn's
  canonical `SecItem` forum threads). Error-code numerics cross-checked against
  `errsec.tsv`. Already folded into the API sketch and design rules above.
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
- **Two suites (`test/`):** a **unit** suite (`test_unit`, attached to `runtest`)
  that is pure — error `to_string`, `code_of_status`, `wipe`, and the errSec
  guard — no keychain access, so it runs anywhere including sandboxed CI; and an
  **integration** suite (`test_integration`, detached on the `@integration`
  alias) holding all keychain round-trips. Rationale: opam-repository CI *does*
  run `@runtest {with-test}` on macOS workers under a sandbox that blocks
  keychain access (it returns empty/exit-0, per opam#4389), so keychain tests
  would fail there. Keeping them off `runtest` means `dune runtest`, `opam
  install --with-test`, and opam-repo CI all run only the safe unit suite; the
  keychain suite is opt-in via `dune build @integration`. (Precedent: `ca-certs`
  filters its keychain tests off macOS; we're macOS-only so we detach instead.)
- **CI:** GitHub Actions `macos-latest` runner, matrix over a couple of OCaml
  versions, running `dune build @integration` for the real keychain coverage
  (the unit suite runs everywhere). On the unsigned `dune` binary, **`File_based`**
  only — no signing, no entitlements, no Developer account. (Phase 0.5 proved DP
  is unreachable: `-34018` unsigned, *kernel kill* with the entitlement.)
  Phase 0 saw no unlock prompt interactively; validate on a real runner (Q2).
- **Deferred features are not CI-tested.** The `Data_protection` path, biometric
  / `SecAccessControl`, and sync need provisioning + (for biometrics) Touch ID +
  a human. If/when built, they ship with a documented manual checklist, clearly
  labeled "unverified in CI" — never presented as a tested feature.

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

- **Phase 0.5 — Signing/scope probe. ✅ DONE.**
  `spike/dp_probe.*` measured what an unsigned binary can reach (table under
  Scope). Result: file-based works unsigned; the data-protection keychain is
  `-34018` unsigned and kernel-killed with the restricted entitlement. Decision:
  **v1 = file-based only**, DP/biometrics/sync deferred as provisioning-gated.

- **Phase 1 — Generic password MVP (file-based). ✅ DONE.**
  `lib/` (`osx_keychain.ml{,i}` + `keychain_stubs.c`) + `test/`. `Generic_password`
  set/get/mem/delete with upsert (three-dict discipline), idempotent delete,
  named `error` set (`code_of_status` off `errsec.tsv`) +
  `SecCopyErrorMessageString`, `caml_release_runtime_system` around every
  `SecItem*` call, tag-table FFI boundary. Alcotest suite green **9/9** unsigned
  (round-trip, binary fidelity, upsert, missing→`Ok None`, delete, idempotent
  delete, mem, label, + errSec guard validating branch constants against
  `errsec.tsv`). No GUI prompt, no keychain residue. opam file + dune packaging
  in place. Remaining for release polish: README, CI workflow.

- **Phase 2 — Internet passwords & richer queries (file-based). ✅ DONE.**
  `Internet_password` set/get/delete keyed on server/account (+ optional
  protocol/port/path/security_domain), with a `protocol` variant. Attribute
  enumeration (`kSecReturnAttributes` + `kSecMatchLimitAll`) via a new
  `osxkc_copy_attrs` stub → `Generic_password.list` / `Internet_password.list`
  returning identifying attributes only (no secrets, no prompt). Suite green
  **14/14** unsigned, including a primary-key test (same server/account, two
  ports coexist) and enumeration round-trips. No keychain residue.

- **Phase 3 — Ergonomics & docs. ✅ DONE (release plumbing deferred).**
  `to_string` error pretty-printer; `get_bytes` (caller-owned mutable buffer) +
  `wipe` helper with the GC best-effort caveat documented; error type doc note on
  which codes actually surface (incl. the upsert TOCTOU race). `README.md` with
  quickstart, a worked `security`-CLI replacement, internet/enumeration/secret-
  hygiene examples; `examples/readme_examples.ml` compiles those snippets against
  the in-tree lib so the docs can't drift. Suite green **15/15**.
  Deferred to "tomorrow" (explicit user call): CI workflow, opam-repository
  submission, optional `osx-keychain-lwt`.

- **Deferred (post-v1, only with a signed-app consumer + a way to test):**
  the `Data_protection` backend, `kSecAttrAccessible` classes,
  `SecAccessControlCreateWithFlags` biometric/`LAContext` gating,
  `kSecAttrSynchronizable` / iCloud, access groups. Kept reachable by the
  `backend`/`synchronizable` params already in the API; shipped (if ever) labeled
  experimental + manual-test-only.

## Open questions

1. ~~`cf` coverage vs. vendoring~~ — **resolved (Phase 0): no CF dependency; CF
   manipulation lives in the C stubs.**
2. ~~DP keychain in CI~~ — **resolved (Phase 0.5): DP is unreachable unsigned;
   no CI lane.** Still open: does a headless CI runner have an unlocked login
   keychain for the *file-based* tests, or do we create an isolated test
   keychain? Validate on a real runner.
3. ~~Default backend~~ — **resolved: `File_based` default; DP deferred-experimental.**
4. Whether to expose `SecItemUpdate` directly in v1 or keep it behind upsert only.
5. ~~Secret-erasure story~~ — **resolved (Phase 3): `get_bytes` + `wipe`, with the
   GC best-effort limitation documented; secrets stay `string` by default.**
