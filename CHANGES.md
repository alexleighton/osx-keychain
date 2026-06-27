## 1.0.0 (2026-06-26)

Initial release.

- Typed bindings to the macOS Keychain Services `SecItem*` API via hand-written
  C stubs over `Security.framework`.
- `Generic_password` and `Internet_password` modules: `set` (add-or-update
  upsert), `get` / `get_bytes` / `with_secret`, `delete` (idempotent), and
  `list` attribute enumeration; `Generic_password` additionally has `mem`.
  `Internet_password` keys on server/account with optional protocol/port/path/
  security-domain.
- Structured errors: `OSStatus` codes mapped to a typed `error_code` variant,
  every operation returning `(_, error) result`. "Not found" is `Ok None`, not
  an error; `to_string` pretty-prints an error.
- Exact binary round-trip for secrets, including embedded NULs and high bytes.
- Secret-hygiene helpers: `get_bytes` (caller-owned mutable buffer) and `wipe`,
  with the GC best-effort limitation documented.
- Targets the file-based keychain, which works on unsigned binaries with no
  entitlements — the common case for CLI tools and daemons. The
  `Data_protection` backend is reachable via `?backend` but is experimental and
  unverified (requires Apple Developer provisioning).
- macOS only.
