(* The worked examples the README links to (in place of inline snippets), kept
   here so they are type-checked on every build and can't silently drift from the
   API. Not executed by the test suite — `dune build` compiling this file is the
   check; running it would touch the real keychain, so the bodies are [ignore]d. *)

open Osx_keychain

let use _ = ()

let quickstart () =
  (* CLI: security add-generic-password -U -s my-app -a alice -w hunter2
     ([set] is an upsert, hence -U "update if it exists"; note the secret is
     visible in `ps` as a process argument — the library never exposes it). *)
  (match Generic_password.set ~service:"my-app" ~account:"alice" "hunter2" with
   | Ok () -> ()
   | Error e -> prerr_endline (to_string e));
  (* CLI: security find-generic-password -s my-app -a alice -w
     (-w prints only the secret; a missing item exits non-zero rather than the
     library's typed [Ok None]). *)
  match Generic_password.get ~service:"my-app" ~account:"alice" () with
  | Ok (Some secret) -> Printf.printf "got %s\n" secret
  | Ok None -> print_endline "no such item"
  | Error e -> prerr_endline (to_string e)

let replacing_security_cli () =
  (* CLI: security find-generic-password -s example-mail -a you@example.com -w *)
  match Generic_password.get ~service:"example-mail" ~account:"you@example.com" () with
  | Ok (Some app_password) -> use app_password
  | Ok None -> failwith "keychain item missing; add it first"
  | Error e -> failwith (Osx_keychain.to_string e)

let internet () =
  (* CLI: security add-internet-password -U -s imap.example.com -a alice \
            -r imps -P 993 -w app-password
     (-r is the 4-char protocol code: imps = IMAPS, htps = HTTPS, …; -P the port) *)
  ignore
    (Internet_password.set ~server:"imap.example.com" ~account:"alice"
       ~protocol:Imaps ~port:993 "app-password");
  (* CLI: security find-internet-password -s imap.example.com -a alice \
            -r imps -P 993 -w *)
  match
    Internet_password.get ~server:"imap.example.com" ~account:"alice"
      ~protocol:Imaps ~port:993 ()
  with
  | Ok (Some pw) -> ignore pw
  | _ -> ()

let enumeration () =
  (* No real CLI equivalent: `security` has no per-service enumeration. The
     nearest is `security dump-keychain`, which dumps every item (and prompts
     repeatedly); [list] returns just the matching items' attributes, no secrets. *)
  match Generic_password.list ~service:"my-app" () with
  | Ok infos -> List.iter (fun i -> print_endline i.Generic_password.account) infos
  | Error _ -> ()

let secret_hygiene () =
  (* CLI: security find-generic-password -s my-app -a alice -w
     — but the CLI necessarily prints the secret to stdout; [get_bytes] keeps it
     in a buffer you [wipe] when done. *)
  match Generic_password.get_bytes ~service:"my-app" ~account:"alice" () with
  | Ok (Some b) ->
    Fun.protect ~finally:(fun () -> Osx_keychain.wipe b) (fun () -> use b)
  | _ -> ()

(* As [secret_hygiene], but [with_secret] owns the buffer and wipes it for you —
   even if the body raises. The CLI has no equivalent: once `find-generic-password
   -w` writes the secret to stdout there is nothing to scrub. *)
let with_secret_example () =
  match
    Generic_password.with_secret ~service:"my-app" ~account:"alice" (fun b ->
        use b (* buffer is wiped after this returns *))
  with
  | Ok (Some ()) -> ()
  | Ok None -> print_endline "no such item"
  | Error e -> prerr_endline (to_string e)

let () =
  ignore quickstart;
  ignore replacing_security_cli;
  ignore internet;
  ignore enumeration;
  ignore secret_hygiene;
  ignore with_secret_example
