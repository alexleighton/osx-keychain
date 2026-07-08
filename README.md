# osx-keychain

Typed OCaml bindings to the macOS Keychain (`SecItem*` API) for storing and
retrieving passwords — a structured alternative to shelling out to
`/usr/bin/security`.

- **Structured results.** Real `OSStatus` codes and a typed `result`; "not
  found" is `Ok None`, not a string you have to grep for.
- **Exact binary round-trip.** Secrets with embedded NULs / high bytes survive
  intact (the `security` CLI hex-dumps them).
- **No subprocess.** No process spawn per call; secrets don't pass through argv,
  stdout, the process table, or shell history.
- **Tiny dependency footprint.** Hand-written C stubs over `Security.framework`;
  no `ctypes`, no CoreFoundation binding — just `dune`.

📖 **[API documentation](https://alexleighton.github.io/osx-keychain/)**

## Scope

v1 targets the **file-based keychain** (the login keychain reached by the
`security` CLI). It works on **unsigned binaries with no entitlements** — the
common case for CLI tools and daemons.

The data-protection keychain, Touch ID / `SecAccessControl`, and iCloud sync are
**out of scope**: they require an Apple Developer provisioning profile both to
use and to test (an unsigned process gets `errSecMissingEntitlement` or is killed
by the kernel). A `Data_protection` backend parameter exists but is experimental
and unverified. See [`reference/keychain-notes.md`](reference/keychain-notes.md)
(§1, §3) for the full entitlement/provisioning rationale.

macOS only.

## Install

Not yet published to opam. For a hermetic local setup, create a project-local
opam switch from the declared dependencies:

```sh
./scripts/setup-switch.sh   # creates ./_opam with deps (incl. test deps)
eval $(opam env)            # activate it in this shell
dune build
dune runtest                # unit tests — pure, no keychain access
dune build @integration     # integration tests — touch your login keychain
```

The integration suite hits the real login keychain, so it's kept off the default
`runtest` alias (and out of `opam install --with-test` / packaged CI, whose
sandbox blocks keychain access). Run it explicitly with `dune build @integration`.

It cleans up after itself (per-test deletes plus an `at_exit` sweep). If a test
process is ever hard-killed before that runs, sweep up the orphans with
[`scripts/clean-test-keychain.sh`](scripts/clean-test-keychain.sh) (`--dry-run`
to preview) — it deletes only the test-owned items via the `security` CLI.

`setup-switch.sh` is idempotent — re-run it to pick up new dependencies. Pin a
compiler with `OCAML_COMPILER=5.3.0 ./scripts/setup-switch.sh`. If you already
have a suitable switch, just `dune build` / `dune runtest` directly.

In a project, depend on the `osx-keychain` library (module `Osx_keychain`).

## Quickstart

```ocaml
open Osx_keychain

let () =
  (* store (create or overwrite) *)
  (match Generic_password.set ~service:"my-app" ~account:"alice" "hunter2" with
   | Ok () -> ()
   | Error e -> prerr_endline (to_string e));

  (* retrieve *)
  match Generic_password.get ~service:"my-app" ~account:"alice" () with
  | Ok (Some secret) -> Printf.printf "got %s\n" secret
  | Ok None          -> print_endline "no such item"
  | Error e          -> prerr_endline (to_string e)
```

## Usage

Worked examples for every operation below live in
[`examples/readme_examples.ml`](examples/readme_examples.ml), each annotated with
the equivalent `security` CLI command and the `Security.framework` call it
exposes. That file is compiled on every `dune build`, so it never drifts from the
API. (It is compiled, not run — executing it would touch your real keychain; the
round-trips are exercised by the integration suite instead.)

- **Generic passwords.** `Generic_password.set ~service ~account secret` stores
  the item (upsert — create, or overwrite if `(service, account)` exists); `get`
  returns `Ok (Some secret)` / `Ok None`; `delete` is idempotent (removing a
  missing item is `Ok ()`).
- **Replacing a `security` call.** `Generic_password.get` is the structured
  stand-in for `security find-generic-password -s … -a … -w` — `Ok None` instead
  of a non-zero exit, no subprocess, and no secret on stdout or in `ps`.
- **Internet passwords.** `Internet_password.*` are keyed by `server` +
  `account` plus optional `protocol` / `port` / `path` / `security_domain`
  (together the keychain's primary key — pass the same identifying attributes to
  `get`/`delete` that you used for `set`).
- **Enumeration.** `Generic_password.list` / `Internet_password.list` return
  items' identifying attributes only — metadata, no secrets, so no prompt.
- **Secret hygiene.** `get_bytes` hands back a `bytes` buffer you can `wipe`
  after use; `with_secret` runs a callback over a library-owned buffer and wipes
  it for you, even if the callback raises. Best-effort: OCaml's GC may have made
  transient copies `wipe` can't reach, and the OS holds the secret regardless.

## Error handling

Every operation returns `(_, error) result`. An `error` carries the raw
`OSStatus` (`status`), a named classification (`code`), and the system message;
`to_string` renders all three. Because expected outcomes are folded into `Ok`
(missing → `Ok None`, duplicate-on-`set` → handled by update), an `Error`
usually signals a genuine failure — `Auth_failed`, `Interaction_not_allowed`,
`Missing_entitlement`, `Param`, … `code_of_status` classifies any raw `OSStatus`.

## License

MIT — see [LICENSE](LICENSE).
