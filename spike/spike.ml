(* Phase 0 spike driver: exercise the SecItem* round-trip from OCaml. *)

external set : string -> string -> string -> int = "okc_set"
external get : string -> string -> int * string = "okc_get"
external delete : string -> string -> int = "okc_delete"

let err_sec_success = 0
let err_sec_item_not_found = -25300

let service = "com.osx-keychain.spike"
let account = "phase0"

(* Binary-faithful payload: embedded NUL, high bytes, UTF-8 — exactly the
   kind of secret the `security` CLI mangles via hex-dump. *)
let secret = "s3cr3t\x00\xff\xfe\xc3\xa9 end"

let check name cond = Printf.printf "[%s] %s\n" (if cond then "PASS" else "FAIL") name

let () =
  (* clean slate (ignore not-found) *)
  ignore (delete service account);

  let st = set service account secret in
  check "set returns errSecSuccess" (st = err_sec_success);

  let st, got = get service account in
  check "get returns errSecSuccess" (st = err_sec_success);
  check "get round-trips bytes exactly" (got = secret);
  Printf.printf "      got %d bytes (expected %d)\n"
    (String.length got) (String.length secret);

  (* upsert: overwrite with a new value *)
  let secret2 = "rotated-value" in
  let st = set service account secret2 in
  check "upsert (update) returns errSecSuccess" (st = err_sec_success);
  let _, got2 = get service account in
  check "upsert reflected on read" (got2 = secret2);

  let st = delete service account in
  check "delete returns errSecSuccess" (st = err_sec_success);

  let st, _ = get service account in
  check "get after delete is errSecItemNotFound"
    (st = err_sec_item_not_found);

  Printf.printf "\nOSStatus reference: success=%d notFound=%d\n"
    err_sec_success err_sec_item_not_found
