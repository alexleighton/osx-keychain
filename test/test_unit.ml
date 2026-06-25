(* Pure unit tests — no keychain access, so they run anywhere, including the
   sandboxed opam-repository CI. Attached to the default `runtest` alias. *)

open Osx_keychain

let test_to_string () =
  let e = { status = -25300; code = Item_not_found; message = "no such item" } in
  Alcotest.(check string) "rendered error"
    "Item_not_found (OSStatus -25300): no such item"
    (to_string e)

let test_classify () =
  Alcotest.(check bool) "unknown status -> Other" true (code_of_status 999999 = Other);
  Alcotest.(check bool) "success (0) is not an error code" true (code_of_status 0 = Other)

let test_wipe () =
  let b = Bytes.of_string "secret" in
  wipe b;
  Alcotest.(check string) "buffer zeroed" (String.make 6 '\000') (Bytes.to_string b)

(* Guard: the OSStatus values the library branches on must match the SDK header
   values extracted into reference/errsec.tsv. Verifies by name, so a transposed
   number fails loudly. Reads the TSV path dune supplies via the environment. *)
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
  let guard =
    match Sys.getenv_opt "OSX_KEYCHAIN_ERRSEC_TSV" with
    | Some _ -> [ case "errSec values match SDK" test_errsec_guard ]
    | None -> []
  in
  Alcotest.run "osx-keychain-unit"
    [ ("error",
       [ case "to_string" test_to_string;
         case "code_of_status fallback" test_classify;
         case "wipe" test_wipe ]);
      ("guard", guard) ]
