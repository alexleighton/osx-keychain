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

(* Guard: every kSec* key keychain_stubs.c references must exist in
   reference/ksec.tsv (extracted from the SDK), so a mistyped key — which the C
   compiler accepts as an extern and only fails at link/runtime — fails loudly
   here instead. The names live in C (not OCaml values), so we scrape them from
   the source and check membership. Paths come from the environment via dune. *)
let read_file path =
  let ic = open_in_bin path in
  Fun.protect ~finally:(fun () -> close_in_noerr ic) (fun () ->
    really_input_string ic (in_channel_length ic))

let is_alnum c =
  (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')

let is_ident_char c = is_alnum c || c = '_'

(* Distinct identifiers matching [kSec][A-Za-z0-9]* that begin a token. *)
let ksec_idents s =
  let n = String.length s in
  let seen = Hashtbl.create 64 in
  let i = ref 0 in
  while !i < n do
    if
      !i + 4 <= n
      && String.sub s !i 4 = "kSec"
      && (!i = 0 || not (is_ident_char s.[!i - 1]))
    then begin
      let j = ref (!i + 4) in
      while !j < n && is_alnum s.[!j] do incr j done;
      (* Require at least one char after "kSec" — a bare "kSec" is prose (e.g. a
         "kSec* keys" comment), not a symbol. *)
      if !j > !i + 4 then Hashtbl.replace seen (String.sub s !i (!j - !i)) ();
      i := !j
    end
    else incr i
  done;
  Hashtbl.fold (fun k () acc -> k :: acc) seen []

let parse_names path =
  let tbl = Hashtbl.create 256 in
  let ic = open_in path in
  Fun.protect ~finally:(fun () -> close_in_noerr ic) (fun () ->
    (try ignore (input_line ic) with End_of_file -> ());
    try
      while true do
        match String.split_on_char '\t' (input_line ic) with
        | name :: _ when String.trim name <> "" ->
          Hashtbl.replace tbl (String.trim name) ()
        | _ -> ()
      done
    with End_of_file -> ());
  tbl

let test_ksec_guard () =
  match
    (Sys.getenv_opt "OSX_KEYCHAIN_KSEC_TSV", Sys.getenv_opt "OSX_KEYCHAIN_STUBS_C")
  with
  | Some tsv, Some stubs ->
    let known = parse_names tsv in
    let used = ksec_idents (read_file stubs) in
    (* A wrong path would scrape nothing and pass vacuously; require a baseline. *)
    Alcotest.(check bool) "found kSec* references in the stubs" true (used <> []);
    let missing = List.filter (fun n -> not (Hashtbl.mem known n)) used in
    Alcotest.(check (list string)) "every kSec* key is in ksec.tsv" []
      (List.sort compare missing)
  | _ -> Alcotest.fail "ksec TSV or stubs path not provided"

let () =
  let case name f = Alcotest.test_case name `Quick f in
  let guard =
    (match Sys.getenv_opt "OSX_KEYCHAIN_ERRSEC_TSV" with
     | Some _ -> [ case "errSec values match SDK" test_errsec_guard ]
     | None -> [])
    @
    match
      (Sys.getenv_opt "OSX_KEYCHAIN_KSEC_TSV", Sys.getenv_opt "OSX_KEYCHAIN_STUBS_C")
    with
    | Some _, Some _ -> [ case "kSec names exist in ksec.tsv" test_ksec_guard ]
    | _ -> []
  in
  Alcotest.run "osx-keychain-unit"
    [ ("error",
       [ case "to_string" test_to_string;
         case "code_of_status fallback" test_classify;
         case "wipe" test_wipe ]);
      ("guard", guard) ]
