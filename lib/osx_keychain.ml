(* See osx_keychain.mli for the public contract. *)

(* Boundary tags — keep in sync with keychain_stubs.c. *)
let k_service = 1
let k_account = 2
let k_label = 3
let k_data = 4

let i_class = 100
let i_match_limit = 101
let i_return_data = 102
let i_use_dp = 103

external c_add : (int * string) array -> (int * int) array -> int = "osxkc_add"

external c_copy_data :
  (int * string) array -> (int * int) array -> int * string = "osxkc_copy_data"

external c_update :
  (int * string) array -> (int * int) array ->
  (int * string) array -> (int * int) array -> int = "osxkc_update"

external c_delete : (int * string) array -> (int * int) array -> int
  = "osxkc_delete"

external c_error_message : int -> string = "osxkc_error_message"

(* OSStatus codes we branch on. Values come from reference/errsec.tsv; the test
   suite's guard asserts these agree with the SDK headers. *)
let err_success = 0
let err_item_not_found = -25300
let err_duplicate_item = -25299

type backend =
  | File_based
  | Data_protection

type error_code =
  | Item_not_found
  | Duplicate_item
  | Auth_failed
  | User_canceled
  | Interaction_not_allowed
  | Missing_entitlement
  | Param
  | Other

let code_of_status = function
  | -25300 -> Item_not_found
  | -25299 -> Duplicate_item
  | -25293 -> Auth_failed
  | -128 -> User_canceled
  | -25308 -> Interaction_not_allowed
  | -34018 -> Missing_entitlement
  | -50 -> Param
  | _ -> Other

type error = {
  status : int;
  code : error_code;
  message : string;
}

let error status =
  { status; code = code_of_status status; message = c_error_message status }

module Generic_password = struct
  (* Generic-password class, plus the data-protection flag when requested. *)
  let class_attrs ~backend extra =
    let dp = match backend with File_based -> [] | Data_protection -> [ (i_use_dp, 1) ] in
    Array.of_list (((i_class, 0) :: dp) @ extra)

  let id_attrs ~service ~account =
    [ (k_service, service); (k_account, account) ]

  let set ?(backend = File_based) ?label ~service ~account secret =
    let add_s =
      let l = (k_data, secret) :: id_attrs ~service ~account in
      let l = match label with Some x -> (k_label, x) :: l | None -> l in
      Array.of_list l
    in
    let st = c_add add_s (class_attrs ~backend []) in
    if st = err_success then Ok ()
    else if st = err_duplicate_item then begin
      (* Upsert: match the primary key, update only the changed attributes.
         kSecValueData goes in the update dict, never the match query. *)
      let q_s = Array.of_list (id_attrs ~service ~account) in
      let u_s =
        let l = [ (k_data, secret) ] in
        let l = match label with Some x -> (k_label, x) :: l | None -> l in
        Array.of_list l
      in
      let st = c_update q_s (class_attrs ~backend []) u_s [||] in
      if st = err_success then Ok () else Error (error st)
    end
    else Error (error st)

  let get ?(backend = File_based) ~service ~account () =
    let q_s = Array.of_list (id_attrs ~service ~account) in
    let q_i = class_attrs ~backend [ (i_return_data, 1); (i_match_limit, 1) ] in
    let st, data = c_copy_data q_s q_i in
    if st = err_success then Ok (Some data)
    else if st = err_item_not_found then Ok None
    else Error (error st)

  let mem ?(backend = File_based) ~service ~account () =
    let q_s = Array.of_list (id_attrs ~service ~account) in
    let q_i = class_attrs ~backend [ (i_match_limit, 1) ] in
    let st, _ = c_copy_data q_s q_i in
    if st = err_success then Ok true
    else if st = err_item_not_found then Ok false
    else Error (error st)

  let delete ?(backend = File_based) ~service ~account () =
    let q_s = Array.of_list (id_attrs ~service ~account) in
    let st = c_delete q_s (class_attrs ~backend []) in
    if st = err_success || st = err_item_not_found then Ok ()
    else Error (error st)
end
