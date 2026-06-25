# macOS Keychain Services — Behavioral Notes for an OCaml `SecItem*` Binding

A working engineer's reference to the things the `<Security/SecItem.h>` headers do **not**
tell you. This is about runtime behavior, not signatures. Every non-obvious claim is cited.

The single most useful primary source is Apple DTS engineer Quinn's pair of forum posts,
which Apple now treats as the canonical narrative documentation for `SecItem`:

- **SecItem: Fundamentals** — <https://developer.apple.com/forums/thread/724023>
- **SecItem: Pitfalls and Best Practices** — <https://developer.apple.com/forums/thread/724013>
- **On Mac Keychains** — <https://developer.apple.com/forums/thread/696431>

Read those three. Everything below condenses and cross-references them.

---

## 1. Data-protection keychain vs. legacy file-based keychain

macOS has **two keychain implementations** reachable through the one `SecItem*` API:

- **File-based keychain** ("legacy", `login.keychain-db`): the traditional Mac keychain.
  Access control is via ACLs (`SecAccess`). No entitlements required. Reachable by daemons.
- **Data-protection keychain** ("DP keychain"): the iOS-style keychain, brought to macOS
  with iCloud Keychain in 10.9. Access control is via *keychain access groups* +
  `SecAccessControl`, driven by **code-signing entitlements**. Only available in a user
  login context (not from a launchd system daemon).
  (<https://developer.apple.com/forums/thread/696431>)

### What `kSecUseDataProtectionKeychain` does, and the default

`kSecUseDataProtectionKeychain` is a boolean query key that routes a `SecItem*` call to the
data-protection keychain. Per Apple: *"The SecItem API talks to the data protection keychain
if you supply either the `kSecUseDataProtectionKeychain` or the `kSecAttrSynchronizable`
attribute. If not, it talks to the file-based keychain."*
(<https://developer.apple.com/forums/thread/696431>)

**So the default target on macOS is the file-based keychain.** This is the opposite of what
most people porting iOS code expect. On iOS there is only one keychain and the key is a no-op.

### Why it matters / behavioral differences

- The `SecItem` API is *aligned with* the DP keychain. Against the file-based keychain it goes
  through a **shim with limitations and bugs**; some attributes/behaviors don't map cleanly.
  (<https://developer.apple.com/forums/thread/696431>)
- DP keychain is the **only** one supporting biometric (Touch ID/Face ID) protection,
  Secure Enclave key protection, and iCloud Keychain sync. (ibid.)
- **Dangerous `SecItemDelete` divergence:** without a `kSecMatchLimit`, the DP keychain
  deletes *all* matching items, while the file-based keychain deletes only *one*.
  (<https://developer.apple.com/forums/thread/696431>) A delete that omits
  `kSecUseDataProtectionKeychain` can also hit items belonging to *other apps or the system*
  in the file-based keychain — Apple explicitly warns this is "very dangerous".
  (<https://developer.apple.com/forums/thread/724013>)
- `SecKeychainCreate` and much of the file-based API were deprecated in macOS 12; the
  file-based keychain is "on the road to deprecation" though not yet formally deprecated.
  (<https://developer.apple.com/forums/thread/696431>)

### When you *must* use the DP keychain

- Any biometric/`SecAccessControl`-protected item, Secure Enclave key, or iCloud sync.
- Porting iOS keychain code unchanged.
- Mac Catalyst apps and "iOS apps on Mac" — they *only* see the DP keychain. (ibid.)

### Implication for our binding's defaults

**Default to setting `kSecUseDataProtectionKeychain = true` on every operation** (add, copy,
update, delete), and make it the documented norm. Rationale: it is the non-deprecated, well-
aligned, iOS-consistent path, and it walls our deletes/queries off from the shared system
file-based keychain. The big caveat — see §3 — is that the DP keychain **requires
entitlements**, so an unsigned/library/test binary can't use it without setup. Therefore the
binding should expose the choice explicitly (e.g. a `~data_protection:bool` param) with DP as
the recommended default, and document the entitlement requirement loudly.

---

## 2. The `errSecDuplicateItem` upsert dance

`SecItemAdd` returns `errSecDuplicateItem` (-25299) when an item already exists whose
**primary-key attributes** match — *regardless of whether the value data differs*. There is no
"add or replace" call; you must implement upsert yourself.

### What defines uniqueness (primary keys per class)

The uniqueness constraint is **class-specific** and is listed on the
[`errSecDuplicateItem` page](https://developer.apple.com/documentation/security/errsecduplicateitem)
(<https://developer.apple.com/forums/thread/724023>):

- **`kSecClassGenericPassword`**: `kSecAttrService` + `kSecAttrAccount`.
  (Confirmed by Apple DTS: <https://developer.apple.com/forums/thread/46429>)
- **`kSecClassInternetPassword`**: `kSecAttrAccount` + `kSecAttrSecurityDomain` +
  `kSecAttrServer` + `kSecAttrProtocol` + `kSecAttrAuthenticationType` + `kSecAttrPort` +
  `kSecAttrPath`. (<https://developer.apple.com/forums/thread/46429>)

**Critical gotcha:** attributes *not* in the primary key do **not** affect uniqueness. Apple's
worked example shows code that `SecItemCopyMatching`-es on `kSecAttrGeneric` (which is *not* a
generic-password primary key), gets `errSecItemNotFound`, then `SecItemAdd`s and gets
`errSecDuplicateItem` anyway — because the service/account already exist. Query and add on the
*same* attribute set you consider to define identity.
(<https://developer.apple.com/forums/thread/724013>)

### Correct add-then-update pattern

```
add_query  = { class; <primary-key attrs>; kSecValueData = data; kSecUseDataProtectionKeychain }
status = SecItemAdd(add_query, NULL)
if status == errSecDuplicateItem:
    match_query  = { class; <primary-key attrs>; kSecUseDataProtectionKeychain }   # NO value, NO return keys
    attrs_to_set = { kSecValueData = data }                                        # ONLY what changes
    status = SecItemUpdate(match_query, attrs_to_set)
```

Try-add-first is generally preferable to copy-then-add because it avoids a TOCTOU race and one
round trip.

### Pitfalls

- **Keep the three dictionaries separate.** A *query* dict (what to match), an *update* dict
  (what to change), and an *add* dict serve different purposes. Apple explicitly warns against
  reusing one mutable dictionary across calls — e.g. leaving `kSecReturnData`/`kSecReturnAttributes`
  in a dict you then hand to `SecItemAdd`, or leaving `kSecValueData` in your match query.
  (<https://developer.apple.com/forums/thread/724013>)
- **`kSecValueData` goes in the attributes-to-update dict for `SecItemUpdate`, never in the
  match query.** Putting value/meta attributes in the match query forces the keychain to
  decompose them and changes matching semantics. (ibid.)
- **`SecItemUpdate` is a bulk operation.** If your match query is under-specified it can update
  *more than one* item. Apple: *"if your query dictionary matches more than you intended, you
  might end up moving items unexpectedly … test it thoroughly."* Include the full primary key.
  (<https://developer.apple.com/forums/thread/724013>)

---

## 3. Codesigning & entitlements — the `-34018` / `errSecMissingEntitlement` trap

This is the single biggest footgun for a *library* (vs. an app bundle), so be thorough.

### The rule

- **File-based keychain: never requires entitlements.** Apple DTS: *"If you're using the
  traditional file-based keychain, you should never see error -34018."*
  (<https://developer.apple.com/forums/thread/114456>)
- **Data-protection keychain: requires entitlements.** Access is gated by *keychain access
  groups*, which the system derives **only from the code signature**, from three entitlements:
  `application-identifier` (a.k.a. `com.apple.application-identifier` on macOS),
  `keychain-access-groups`, and (iOS-family only) `com.apple.security.application-groups`.
  If the requested/default access group isn't in one of those, you get
  `errSecMissingEntitlement` (-34018). (<https://developer.apple.com/forums/thread/114456>)

So: **the moment you set `kSecUseDataProtectionKeychain` on an unsigned or improperly-signed
binary, adds/queries can fail with -34018**, because there's no entitled access group to use.

### Unsigned / ad-hoc-signed binaries

- A binary with **no entitlements** has no keychain access group, so DP-keychain `SecItemAdd`
  fails with -34018; with an entitlements file (even containing a private/test access group) it
  works. (<https://developer.apple.com/forums/thread/114456>,
  <https://github.com/kishikawakatsumi/KeychainAccess/issues/52>)
- Entitlements are embedded **at signing time**. The `.entitlements` file in your project is
  only an *input*; what matters is what's actually in the signature. Verify with:
  `codesign -d --entitlements :- /path/to/binary`
  (<https://developer.apple.com/forums/thread/114456>)
- On Apple Silicon, all binaries are at least ad-hoc signed, but ad-hoc signatures generally
  **cannot carry the provisioned `application-identifier`/`keychain-access-groups`** that a real
  Team ID gives you; for a real shared access group you need a Developer ID / development cert
  plus a provisioning profile.

### What works *without* entitlements

- The **file-based keychain** (the default path — i.e. *omit* `kSecUseDataProtectionKeychain`).
  Generic/internet password add/copy/update/delete all work unsigned here. This is why it's a
  viable fallback for libraries and CI.

### Impact on testing/CI of an OCaml library (not an app bundle)

- Unit tests and CI runners typically run an **unsigned or ad-hoc `dune exec` / test binary**.
  If your tests exercise the DP keychain, expect **-34018** unless you sign the test binary with
  entitlements (and on macOS a self-signed cert can grant a `keychain-access-groups` entry for
  local testing).
- Practical strategy for the binding:
  1. Make the keychain target selectable; **default tests to the file-based keychain** (no
     entitlements needed) so CI is green out of the box, *or*
  2. Provide a signing step in CI: write a minimal `.entitlements` with a `keychain-access-groups`
     entry and `codesign --sign - --entitlements test.entitlements <binary>` (self-signed works
     for local DP-keychain access on macOS), then run.
- Map -34018 to a clearly named error and document "you probably need to sign with entitlements,
  or you're on the DP keychain unintentionally."

---

## 4. `kSecAttrAccessible` accessibility classes

Controls *when* a DP-keychain item's data is readable relative to device lock state. Meaningful
distinctions (<https://developer.apple.com/documentation/security/ksecattraccessiblewhenunlocked>
and the constant pages linked from it; forum overview
<https://developer.apple.com/forums/thread/682669>):

| Constant | Readable when | Migrates to new device (backup/restore) |
|---|---|---|
| `kSecAttrAccessibleWhenUnlocked` | device unlocked only | yes |
| `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` | device unlocked only | **no** |
| `kSecAttrAccessibleAfterFirstUnlock` | any time after first unlock since boot (incl. while locked) | yes |
| `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` | as above | **no** |
| `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` | unlocked **and** a passcode is set; item is wiped if the passcode is removed; never leaves the device | **no** |
| `kSecAttrAccessibleAlways` / `…AlwaysThisDeviceOnly` | always, even locked | **deprecated** |

- **`WhenUnlocked` is the default** when you don't set the attribute.
  (<https://developer.apple.com/forums/thread/682669>)
- The **`Always*` classes are deprecated** (they ignore lock state entirely); do not use them.
  (<https://developer.apple.com/forums/thread/682669>)
- `…ThisDeviceOnly` variants are excluded from encrypted backups and iCloud Keychain, so the
  secret can't escape the device — at the cost of not surviving device migration.
- Use **`AfterFirstUnlock`** if the item must be read by background/daemon work while the screen
  is locked; otherwise the read fails with `errSecInteractionNotAllowed` (-25308).
  (<https://developer.apple.com/forums/thread/724013>)

**Sensible default for the binding: `kSecAttrAccessibleWhenUnlocked`** — matches the system
default and is the least-surprising/most-secure baseline. Offer `AfterFirstUnlock` for
background use and a `…ThisDeviceOnly` toggle for non-migratable secrets.

> Note: on macOS, lock-state semantics are weaker than on iOS (the Mac's "locked" state and key
> hierarchy differ). Treat accessibility as primarily a backup/migration and policy control on
> macOS rather than a hard runtime guarantee.

---

## 5. Access control & biometrics (`SecAccessControlCreateWithFlags`, `LAContext`)

To require user authentication (biometrics/passcode) to release an item, set
`kSecAttrAccessControl` instead of (it *supersedes*) `kSecAttrAccessible`. You build the object
with `SecAccessControlCreateWithFlags(allocator, protection, flags, error)`, where `protection`
is one of the `kSecAttrAccessible*` constants and `flags` are the constraint flags below.
(<https://developer.apple.com/documentation/security/secaccesscontrolcreatewithflags(_:_:_:_:)>)

- **`kSecAttrAccessControl` and `kSecAttrAccessible` are mutually exclusive in the add dict** —
  the accessibility is the *first argument* to `SecAccessControlCreateWithFlags`, so don't also
  pass `kSecAttrAccessible` or you get `errSecParam`.

### Flags (`SecAccessControlCreateFlags`)

(<https://developer.apple.com/documentation/security/secaccesscontrolcreateflags>)

- `.biometryAny` — any currently/future enrolled biometry.
- `.biometryCurrentSet` — biometry, **invalidated if the enrolled set changes** (adding/removing
  a fingerprint or re-enrolling Face ID destroys access to the item). Strongest anti-tamper
  binding. No passcode fallback.
  (<https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometrycurrentset>)
- `.userPresence` — biometry **with passcode fallback** (biometry first, then device passcode).
- `.devicePasscode` — passcode only.
- `.or` / `.and` — combine constraints, e.g. `[.biometryCurrentSet, .or, .devicePasscode]`.
- `.applicationPassword` — additionally gate on an app-supplied password.
  (combination guidance: <https://medium.com/@alx.gridnev/biometry-protected-entries-in-ios-keychain-6125e130e0d5>)

### The prompt blocks; `LAContext` reuse

- A `SecItemCopyMatching` on an access-control-protected item **synchronously presents the
  auth UI and blocks until the user responds**. Apple/community guidance: run it on a
  background thread, never the main/UI thread.
  (<https://developer.apple.com/forums/thread/103380>; see §7)
- Supply a reusable `LAContext` via `kSecUseAuthenticationContext` to (a) set a prompt string
  (`context.localizedReason` / `kSecUseOperationPrompt`) and (b) **avoid re-prompting**:
  `LAContext.touchIDAuthenticationAllowableReuseDuration` lets a recent successful auth (up to
  `LATouchIDAuthenticationMaximumAllowableReuseDuration`, 5 minutes) satisfy subsequent reads
  without a new prompt. (<https://developer.apple.com/documentation/LocalAuthentication/accessing-keychain-items-with-face-id-or-touch-id>)
- One auth'd `LAContext` can also gate multiple reads. Note that a fresh `LAContext` per call =
  a fresh prompt per call.

### Macs without Touch ID

- On a Mac with **no Touch ID hardware**, a `.biometryAny`/`.biometryCurrentSet` item with no
  passcode fallback is effectively unreadable; include `.or .devicePasscode` (or use
  `.userPresence`) so the user can authenticate with the login password.
  (<https://developer.apple.com/forums/thread/66615>)
- A no-Touch-ID Mac can also pair with an **Apple Watch** for approval in some flows, but you
  cannot rely on it. Probe availability with
  `LAContext.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error:)` before
  committing to a biometry-only ACL, and fall back to passcode otherwise.

---

## 6. `kSecAttrSynchronizable` / iCloud Keychain

`kSecAttrSynchronizable` marks an item to sync via iCloud Keychain. **Setting it (any value)
also routes the call to the DP keychain** (see §1).

### The tri-state in *queries* — the silent-mismatch trap

(<https://developer.apple.com/documentation/security/ksecattrsynchronizable>, confirmed via the
constant's documented behavior)

- **Absent, or `kCFBooleanFalse`**: query matches **non-synchronizable items only**.
  *Synchronizable items will not be returned.*
- **`kCFBooleanTrue`**: query matches **synchronizable items only**.
- **`kSecAttrSynchronizableAny`**: matches **both**.

This is the classic "my item vanished" bug: you add an item with `kSecAttrSynchronizable=true`,
then later copy/update/delete with a query that *omits* the key — and it silently doesn't match,
because the default query is non-synchronizable-only. The reverse happens too. **The
synchronizable flag must be consistent (or use `…Any`) across add/copy/update/delete.**

Implication for the binding: track and pass the synchronizable state on every operation, or
expose a `~synchronizable:[ `Yes | `No | `Any ]` parameter that defaults to `No`. For
*delete/cleanup* paths, `…Any` is often what you actually want.

### Entitlement requirements & limits

- iCloud Keychain sync needs the **iCloud Keychain capability / `com.apple.developer.aps-…`**
  family of entitlements and the user's iCloud Keychain enabled; without proper provisioning
  the DP-keychain access-group rules from §3 still apply (-34018).
- **Only password items sync.** Certificates and cryptographic keys are *not* synchronized even
  if marked synchronizable. (<https://developer.apple.com/forums/thread/696431>)
- `…ThisDeviceOnly` accessibility classes never sync (by definition).

---

## 7. Threading / blocking

- **`SecItem*` calls are synchronous and do IPC to `securityd`** (the daemon that owns the
  keychain). The call blocks on that round trip.
  (<https://developer.apple.com/forums/thread/103380>)
- If the item is protected by `kSecAttrAccessControl`, the call **additionally blocks on user
  authentication UI** (Touch ID / Face ID / passcode), which can take arbitrarily long.
- Community + DTS guidance: **never call `SecItem*` on the main/UI thread**; do it on a
  background thread to avoid hangs. (<https://developer.apple.com/forums/thread/103380>)

**Implication for the OCaml binding:** because every `SecItem*` call can block (IPC, and
potentially an indefinite UI prompt), **release the OCaml runtime lock around the call**
(`caml_release_runtime_system()` / `caml_enter_blocking_section()` before, re-acquire after).
Otherwise a biometric prompt freezes the entire OCaml runtime — no other thread, GC, or signal
handling proceeds while the dialog is up. Do not allocate or touch OCaml values while the lock
is released. (This is the standard `Begin/End_roots` + blocking-section pattern.)

---

## 8. Important `errSec*` codes to map

Numeric values verified against Apple's `SecBase.h`
(<https://github.com/aosm/Security/blob/master/Security/libsecurity_keychain/lib/SecBase.h>) and
osstatus.com (<https://www.osstatus.com/>).

| Constant | Value | Meaning / when you hit it |
|---|---:|---|
| `errSecSuccess` | `0` | OK |
| `errSecUnimplemented` | `-4` | Function not implemented |
| `errSecParam` | `-50` | Bad parameter / malformed query dict (e.g. accessible + accessControl together) |
| `errSecAllocate` | `-108` | Memory allocation failure |
| `errSecUserCanceled` | `-128` | User dismissed/cancelled the auth prompt (distinct from auth failure) — <https://developer.apple.com/documentation/security/errsecusercanceled> |
| `errSecNotAvailable` | `-25291` | No keychain available (e.g. no login keychain in context) |
| `errSecAuthFailed` | `-25293` | Authentication/authorization failed (wrong passcode, biometry failed) |
| `errSecDuplicateItem` | `-25299` | Primary-key collision on `SecItemAdd` → do the upsert (§2) |
| `errSecItemNotFound` | `-25300` | No matching item (normal "not found" on copy/update/delete) |
| `errSecInteractionNotAllowed` | `-25308` | Item not accessible now (device locked vs. accessibility class, or no UI allowed) — do **not** treat as "delete and reset" (§4) |
| `errSecDecode` | `-26275` | Unable to decode the provided data |
| `errSecMissingEntitlement` | `-34018` | DP keychain access denied — no/incorrect signing entitlement (§3) |

Notes:
- `errSecUserCanceled` (-128) is the OSStatus form of the classic `userCanceledErr`; it comes
  back from biometric/passcode-gated reads when the user cancels. Map it separately from
  `errSecAuthFailed` so callers can distinguish "user said no" from "auth was wrong".
  (<https://github.com/square/Valet/issues/143>)
- `errSecInteractionNotAllowed` is the one most likely to be mishandled destructively — see the
  "don't delete the user's credential" warning in §4
  (<https://developer.apple.com/forums/thread/724013>).

---

### Source conflicts / caveats

- The exact `kSecClassInternetPassword` primary-key list is consistent across Apple DTS forum
  posts and the `errSecDuplicateItem` doc, but Apple recommends you *always supply all*
  primary-key attributes regardless, since under-specified queries are the root of most
  duplicate/over-match bugs. (<https://developer.apple.com/forums/thread/46429>)
- macOS lock-state and biometric semantics differ from iOS in ways Apple documents only
  loosely; treat §4/§5 device-lock guarantees as weaker on macOS than the constant names imply.
