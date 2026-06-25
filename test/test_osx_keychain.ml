(* Integration tests — these hit the real login (file-based) keychain. Each test
   works under a per-process service name and cleans up after itself. *)

open Osx_keychain

let service = Printf.sprintf "com.osx-keychain.test.%d" (Unix.getpid ())
let server = Printf.sprintf "test-%d.osx-keychain.invalid" (Unix.getpid ())

(* Unwrap a result, turning a keychain error into a test failure. *)
let ok = function
  | Ok x -> x
  | Error e -> Alcotest.failf "keychain error: status=%d message=%S" e.status e.message

let cleanup account = ignore (Generic_password.delete ~service ~account ())

let opt_string = Alcotest.(option string)

let test_roundtrip () =
  let account = "roundtrip" in
  cleanup account;
  ok (Generic_password.set ~service ~account "hunter2");
  Alcotest.check opt_string "stored secret"
    (Some "hunter2")
    (ok (Generic_password.get ~service ~account ()));
  cleanup account

let test_binary_fidelity () =
  let account = "binary" in
  (* embedded NUL + high bytes + UTF-8 — where the `security` CLI hex-dump fails *)
  let secret = "p\x00ss\xff\xfe\xc3\xa9!" in
  cleanup account;
  ok (Generic_password.set ~service ~account secret);
  Alcotest.check opt_string "exact binary round-trip"
    (Some secret)
    (ok (Generic_password.get ~service ~account ()));
  cleanup account

let test_upsert () =
  let account = "upsert" in
  cleanup account;
  ok (Generic_password.set ~service ~account "first");
  ok (Generic_password.set ~service ~account "second");
  Alcotest.check opt_string "second write wins"
    (Some "second")
    (ok (Generic_password.get ~service ~account ()));
  cleanup account

let test_get_missing () =
  let account = "does-not-exist" in
  cleanup account;
  Alcotest.check opt_string "missing item is Ok None"
    None
    (ok (Generic_password.get ~service ~account ()))

let test_delete_removes () =
  let account = "to-delete" in
  ok (Generic_password.set ~service ~account "x");
  ok (Generic_password.delete ~service ~account ());
  Alcotest.check opt_string "gone after delete"
    None
    (ok (Generic_password.get ~service ~account ()))

let test_delete_idempotent () =
  let account = "never-existed" in
  cleanup account;
  match Generic_password.delete ~service ~account () with
  | Ok () -> ()
  | Error e ->
    Alcotest.failf "deleting a missing item should be Ok, got status=%d" e.status

let test_mem () =
  let account = "mem" in
  cleanup account;
  Alcotest.(check bool) "absent before set" false
    (ok (Generic_password.mem ~service ~account ()));
  ok (Generic_password.set ~service ~account "x");
  Alcotest.(check bool) "present after set" true
    (ok (Generic_password.mem ~service ~account ()));
  cleanup account

let test_label () =
  let account = "label" in
  cleanup account;
  ok (Generic_password.set ~service ~account ~label:"My Label" "x");
  Alcotest.check opt_string "label does not disturb the value"
    (Some "x")
    (ok (Generic_password.get ~service ~account ()));
  cleanup account

let test_generic_list () =
  let svc = service ^ ".list" in
  let accounts = [ "a1"; "a2"; "a3" ] in
  let drop () = List.iter (fun a -> ignore (Generic_password.delete ~service:svc ~account:a ())) accounts in
  drop ();
  List.iter (fun a -> ok (Generic_password.set ~service:svc ~account:a "x")) accounts;
  let listed =
    ok (Generic_password.list ~service:svc ())
    |> List.map (fun (i : Generic_password.info) -> i.account)
    |> List.sort compare
  in
  Alcotest.(check (list string)) "enumerated accounts" accounts listed;
  drop ()

(* Internet passwords ------------------------------------------------------- *)

let test_internet_roundtrip () =
  let account = "alice" in
  let args () = Internet_password.delete ~server ~account ~protocol:Https ~port:443 ~path:"/login" () in
  ignore (args ());
  ok (Internet_password.set ~server ~account ~protocol:Https ~port:443 ~path:"/login" "s3kr3t");
  Alcotest.check opt_string "internet round-trip"
    (Some "s3kr3t")
    (ok (Internet_password.get ~server ~account ~protocol:Https ~port:443 ~path:"/login" ()));
  ok (args ());
  Alcotest.check opt_string "gone after delete"
    None
    (ok (Internet_password.get ~server ~account ~protocol:Https ~port:443 ~path:"/login" ()))

(* port is part of the primary key, so two items with the same server/account
   but different ports must coexist independently. *)
let test_internet_distinct_by_port () =
  let account = "bob" in
  let get port = Internet_password.get ~server ~account ~protocol:Https ~port () in
  let set port v = Internet_password.set ~server ~account ~protocol:Https ~port v in
  let del port = ignore (Internet_password.delete ~server ~account ~protocol:Https ~port ()) in
  del 443; del 8443;
  ok (set 443 "a");
  ok (set 8443 "b");
  Alcotest.check opt_string "port 443" (Some "a") (ok (get 443));
  Alcotest.check opt_string "port 8443" (Some "b") (ok (get 8443));
  del 443; del 8443

let test_internet_upsert () =
  let account = "carol" in
  let del () = ignore (Internet_password.delete ~server ~account ~protocol:Imaps ~port:993 ()) in
  del ();
  ok (Internet_password.set ~server ~account ~protocol:Imaps ~port:993 "first");
  ok (Internet_password.set ~server ~account ~protocol:Imaps ~port:993 "second");
  Alcotest.check opt_string "second write wins"
    (Some "second")
    (ok (Internet_password.get ~server ~account ~protocol:Imaps ~port:993 ()));
  del ()

let test_internet_list () =
  let srv = server ^ ".list" in
  let accounts = [ "u1"; "u2" ] in
  let drop () =
    List.iter (fun a -> ignore (Internet_password.delete ~server:srv ~account:a ~protocol:Https ~port:443 ())) accounts
  in
  drop ();
  List.iter (fun a -> ok (Internet_password.set ~server:srv ~account:a ~protocol:Https ~port:443 "x")) accounts;
  let listed =
    ok (Internet_password.list ~server:srv ())
    |> List.map (fun (i : Internet_password.info) -> i.account)
    |> List.sort compare
  in
  Alcotest.(check (list string)) "enumerated internet accounts" accounts listed;
  drop ()

(* Guard: the OSStatus values the library branches on must match the SDK header
   values extracted into reference/errsec.tsv. Verifies by name, so a transposed
   number fails loudly. Only runs when dune supplies the TSV path. *)
let parse_errsec path =
  let tbl = Hashtbl.create 512 in
  let ic = open_in path in
  Fun.protect ~finally:(fun () -> close_in_noerr ic) (fun () ->
    (try ignore (input_line ic) with End_of_file -> ());
    try
      while true do
        match String.split_on_char '\t' (input_line ic) with
        | name :: value :: _ ->
          (match int_of_string_opt (String.trim value) with
           | Some v -> Hashtbl.replace tbl name v
           | None -> ())
        | _ -> ()
      done
    with End_of_file -> ());
  tbl

let test_errsec_guard () =
  match Sys.getenv_opt "OSX_KEYCHAIN_ERRSEC_TSV" with
  | None -> Alcotest.fail "errsec TSV path not provided"
  | Some path ->
    let tbl = parse_errsec path in
    let cases =
      [ ("errSecItemNotFound", Item_not_found);
        ("errSecDuplicateItem", Duplicate_item);
        ("errSecAuthFailed", Auth_failed);
        ("errSecUserCanceled", User_canceled);
        ("errSecInteractionNotAllowed", Interaction_not_allowed);
        ("errSecMissingEntitlement", Missing_entitlement);
        ("errSecParam", Param) ]
    in
    List.iter
      (fun (name, expected) ->
        match Hashtbl.find_opt tbl name with
        | None -> Alcotest.failf "%s missing from errsec.tsv" name
        | Some v ->
          Alcotest.(check bool)
            (Printf.sprintf "%s (%d) classifies correctly" name v)
            true
            (code_of_status v = expected))
      cases

let () =
  let case name f = Alcotest.test_case name `Quick f in
  let generic =
    [ case "round-trip" test_roundtrip;
      case "binary fidelity" test_binary_fidelity;
      case "upsert" test_upsert;
      case "get missing -> Ok None" test_get_missing;
      case "delete removes" test_delete_removes;
      case "delete is idempotent" test_delete_idempotent;
      case "mem" test_mem;
      case "label" test_label;
      case "list / enumerate" test_generic_list ]
  in
  let internet =
    [ case "round-trip" test_internet_roundtrip;
      case "distinct by port" test_internet_distinct_by_port;
      case "upsert" test_internet_upsert;
      case "list / enumerate" test_internet_list ]
  in
  let guard =
    match Sys.getenv_opt "OSX_KEYCHAIN_ERRSEC_TSV" with
    | Some _ -> [ case "errSec values match SDK" test_errsec_guard ]
    | None -> []
  in
  Alcotest.run "osx-keychain"
    [ ("generic_password", generic);
      ("internet_password", internet);
      ("guard", guard) ]
