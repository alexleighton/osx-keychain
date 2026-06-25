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

## Scope

v1 targets the **file-based keychain** (the login keychain reached by the
`security` CLI). It works on **unsigned binaries with no entitlements** — the
common case for CLI tools and daemons.

The data-protection keychain, Touch ID / `SecAccessControl`, and iCloud sync are
**out of scope**: they require an Apple Developer provisioning profile both to
use and to test (an unsigned process gets `errSecMissingEntitlement` or is killed
by the kernel). A `Data_protection` backend parameter exists but is experimental
and unverified. See [`PLAN.md`](PLAN.md) for the full rationale.

macOS only.

## Install

Not yet published to opam. For a hermetic local setup, create a project-local
opam switch from the declared dependencies:

```sh
./scripts/setup-switch.sh   # creates ./_opam with deps (incl. test deps)
eval $(opam env)            # activate it in this shell
dune build
dune runtest                # integration tests — they touch your login keychain
```

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

`set` is an upsert (create, or overwrite if `(service, account)` already
exists). `delete` is idempotent — removing a missing item is `Ok ()`.

## Replacing a `security` CLI call

A common pattern is shelling out to read a password:

```sh
security find-generic-password -s "example-mail" -a "you@example.com" -w
```

The direct equivalent, with structured errors and no subprocess:

```ocaml
match Generic_password.get ~service:"example-mail" ~account:"you@example.com" () with
| Ok (Some app_password) -> use app_password
| Ok None                -> failwith "keychain item missing; add it first"
| Error e                -> failwith (Osx_keychain.to_string e)
```

## Internet passwords

Identified by `server` + `account`, plus optional `protocol` / `port` / `path` /
`security_domain` (together the keychain's primary key — pass the same ones to
`get`/`delete` that you used for `set`):

```ocaml
let () =
  ignore (Internet_password.set
            ~server:"imap.example.com" ~account:"alice"
            ~protocol:Imaps ~port:993 "app-password");
  match Internet_password.get
          ~server:"imap.example.com" ~account:"alice"
          ~protocol:Imaps ~port:993 () with
  | Ok (Some pw) -> ignore pw
  | _ -> ()
```

## Enumeration

List items' identifying attributes (metadata only — no secrets are read, so no
prompt):

```ocaml
match Generic_password.list ~service:"my-app" () with
| Ok infos -> List.iter (fun i -> print_endline i.Generic_password.account) infos
| Error _  -> ()
```

## Secret hygiene

Secrets are `string` by default. For a buffer you can scrub after use, take the
`bytes` variant and `wipe` it:

```ocaml
match Generic_password.get_bytes ~service:"my-app" ~account:"alice" () with
| Ok (Some b) -> Fun.protect ~finally:(fun () -> Osx_keychain.wipe b) (fun () -> use b)
| _ -> ()
```

This is best-effort: OCaml's GC may have made transient copies `wipe` can't
reach, and the OS holds the secret in its own memory regardless.

## Error handling

Every operation returns `(_, error) result`. An `error` carries the raw
`OSStatus` (`status`), a named classification (`code`), and the system message;
`to_string` renders all three. Because expected outcomes are folded into `Ok`
(missing → `Ok None`, duplicate-on-`set` → handled by update), an `Error`
usually signals a genuine failure — `Auth_failed`, `Interaction_not_allowed`,
`Missing_entitlement`, `Param`, … `code_of_status` classifies any raw `OSStatus`.

## License

MIT — see [LICENSE](LICENSE).
