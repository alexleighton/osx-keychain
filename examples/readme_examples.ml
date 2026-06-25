(* The code snippets from README.md, kept here so they are type-checked on every
   build and can't silently drift from the API. Not executed by the test suite —
   `dune build` compiling this file is the check. *)

open Osx_keychain

let use _ = ()

let quickstart () =
  (match Generic_password.set ~service:"my-app" ~account:"alice" "hunter2" with
   | Ok () -> ()
   | Error e -> prerr_endline (to_string e));
  match Generic_password.get ~service:"my-app" ~account:"alice" () with
  | Ok (Some secret) -> Printf.printf "got %s\n" secret
  | Ok None -> print_endline "no such item"
  | Error e -> prerr_endline (to_string e)

let replacing_security_cli () =
  match Generic_password.get ~service:"example-mail" ~account:"you@example.com" () with
  | Ok (Some app_password) -> use app_password
  | Ok None -> failwith "keychain item missing; add it first"
  | Error e -> failwith (Osx_keychain.to_string e)

let internet () =
  ignore
    (Internet_password.set ~server:"imap.example.com" ~account:"alice"
       ~protocol:Imaps ~port:993 "app-password");
  match
    Internet_password.get ~server:"imap.example.com" ~account:"alice"
      ~protocol:Imaps ~port:993 ()
  with
  | Ok (Some pw) -> ignore pw
  | _ -> ()

let enumeration () =
  match Generic_password.list ~service:"my-app" () with
  | Ok infos -> List.iter (fun i -> print_endline i.Generic_password.account) infos
  | Error _ -> ()

let secret_hygiene () =
  match Generic_password.get_bytes ~service:"my-app" ~account:"alice" () with
  | Ok (Some b) ->
    Fun.protect ~finally:(fun () -> Osx_keychain.wipe b) (fun () -> use b)
  | _ -> ()

let () =
  ignore quickstart;
  ignore replacing_security_cli;
  ignore internet;
  ignore enumeration;
  ignore secret_hygiene
