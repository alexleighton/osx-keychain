(* Integration tests — these hit the real login (file-based) keychain. Each test
   works under a per-process service name and cleans up after itself. *)

open Osx_keychain

let service = Printf.sprintf "com.osx-keychain.test.%d" (Unix.getpid ())
let server = Printf.sprintf "test-%d.osx-keychain.invalid" (Unix.getpid ())

(* Unwrap a result, turning a keychain error into a test failure. *)
let ok = function
  | Ok x -> x
  | Error e -> Alcotest.failf "keychain error: %s" (Osx_keychain.to_string e)

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

let test_get_bytes_and_wipe () =
  let account = "bytes" in
  cleanup account;
  ok (Generic_password.set ~service ~account "wipe-me");
  let b =
    match ok (Generic_password.get_bytes ~service ~account ()) with
    | Some b -> b
    | None -> Alcotest.fail "expected bytes"
  in
  Alcotest.(check string) "bytes match" "wipe-me" (Bytes.to_string b);
  Osx_keychain.wipe b;
  Alcotest.(check string) "wiped to zeros" (String.make 7 '\000') (Bytes.to_string b);
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
      case "get_bytes + wipe" test_get_bytes_and_wipe;
      case "list / enumerate" test_generic_list ]
  in
  let internet =
    [ case "round-trip" test_internet_roundtrip;
      case "distinct by port" test_internet_distinct_by_port;
      case "upsert" test_internet_upsert;
      case "list / enumerate" test_internet_list ]
  in
  Alcotest.run "osx-keychain-integration"
    [ ("generic_password", generic);
      ("internet_password", internet) ]
