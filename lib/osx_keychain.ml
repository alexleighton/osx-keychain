(* See osx_keychain.mli for the public contract. *)

(* Boundary tags — keep in sync with keychain_stubs.c. *)
let k_service = 1
let k_account = 2
let k_label = 3
let k_data = 4
let k_server = 5
let k_path = 6
let k_security_domain = 7

let i_class = 100
let i_match_limit = 101
let i_return_data = 102
let i_use_dp = 103
let i_return_attrs = 104
let i_protocol = 105
let i_port = 106

(* Item classes (I_CLASS values). *)
let class_generic = 0
let class_internet = 1

external c_add : (int * string) array -> (int * int) array -> int = "osxkc_add"

external c_copy_data :
  (int * string) array -> (int * int) array -> int * string = "osxkc_copy_data"

external c_update :
  (int * string) array -> (int * int) array ->
  (int * string) array -> (int * int) array -> int = "osxkc_update"

external c_delete : (int * string) array -> (int * int) array -> int
  = "osxkc_delete"

external c_copy_attrs :
  (int * string) array -> (int * int) array ->
  int * (int * string) array array = "osxkc_copy_attrs"

external c_error_message : int -> string = "osxkc_error_message"

(* OSStatus codes we branch on. Values come from reference/errsec.tsv; the test
   suite's guard asserts these agree with the SDK headers. *)
let err_success = 0
let err_item_not_found = -25300
let err_duplicate_item = -25299

type backend =
  | File_based
  | Data_protection

type protocol =
  | Http | Https | Ftp | Ftps | Smtp
  | Imap | Imaps | Pop3 | Pop3s | Ssh | Ldap | Ldaps

let protocol_to_int = function
  | Http -> 1 | Https -> 2 | Ftp -> 3 | Ftps -> 4 | Smtp -> 5
  | Imap -> 6 | Imaps -> 7 | Pop3 -> 8 | Pop3s -> 9
  | Ssh -> 10 | Ldap -> 11 | Ldaps -> 12

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

(* int-attrs = class + (data-protection flag) + caller-supplied extras. *)
let iattrs ~item_class ~backend extra =
  let dp = match backend with File_based -> [] | Data_protection -> [ (i_use_dp, 1) ] in
  Array.of_list (((i_class, item_class) :: dp) @ extra)

let label_attr = function Some x -> [ (k_label, x) ] | None -> []

(* (tag, string) array from an enumeration result -> attribute lookup. *)
let attr arr tag = List.assoc_opt tag (Array.to_list arr)

module Generic_password = struct
  type info = {
    service : string;
    account : string;
    label : string option;
  }

  let id ~service ~account = [ (k_service, service); (k_account, account) ]

  let set ?(backend = File_based) ?label ~service ~account secret =
    let add_s = Array.of_list (((k_data, secret) :: label_attr label) @ id ~service ~account) in
    let st = c_add add_s (iattrs ~item_class:class_generic ~backend []) in
    if st = err_success then Ok ()
    else if st = err_duplicate_item then begin
      (* Upsert: match the primary key, update only the changed attributes.
         kSecValueData goes in the update dict, never the match query. *)
      let q_s = Array.of_list (id ~service ~account) in
      let u_s = Array.of_list ((k_data, secret) :: label_attr label) in
      let st = c_update q_s (iattrs ~item_class:class_generic ~backend []) u_s [||] in
      if st = err_success then Ok () else Error (error st)
    end
    else Error (error st)

  let get ?(backend = File_based) ~service ~account () =
    let q_s = Array.of_list (id ~service ~account) in
    let q_i = iattrs ~item_class:class_generic ~backend [ (i_return_data, 1); (i_match_limit, 1) ] in
    let st, data = c_copy_data q_s q_i in
    if st = err_success then Ok (Some data)
    else if st = err_item_not_found then Ok None
    else Error (error st)

  let mem ?(backend = File_based) ~service ~account () =
    let q_s = Array.of_list (id ~service ~account) in
    let q_i = iattrs ~item_class:class_generic ~backend [ (i_match_limit, 1) ] in
    let st, _ = c_copy_data q_s q_i in
    if st = err_success then Ok true
    else if st = err_item_not_found then Ok false
    else Error (error st)

  let delete ?(backend = File_based) ~service ~account () =
    let q_s = Array.of_list (id ~service ~account) in
    let st = c_delete q_s (iattrs ~item_class:class_generic ~backend []) in
    if st = err_success || st = err_item_not_found then Ok ()
    else Error (error st)

  let decode arr =
    { service = Option.value ~default:"" (attr arr k_service);
      account = Option.value ~default:"" (attr arr k_account);
      label = attr arr k_label }

  let list ?(backend = File_based) ?service () =
    let q_s = match service with Some s -> [| (k_service, s) |] | None -> [||] in
    let q_i = iattrs ~item_class:class_generic ~backend
        [ (i_return_attrs, 1); (i_match_limit, 2) ] in
    let st, items = c_copy_attrs q_s q_i in
    if st = err_success then Ok (Array.to_list (Array.map decode items))
    else if st = err_item_not_found then Ok []
    else Error (error st)
end

module Internet_password = struct
  type info = {
    account : string;
    server : string option;
    path : string option;
    security_domain : string option;
    label : string option;
  }

  (* Identifying string attrs. Protocol/port are int-valued (see iattrs'). *)
  let id ~server ~account ?path ?security_domain () =
    let l = [ (k_server, server); (k_account, account) ] in
    let l = match path with Some p -> (k_path, p) :: l | None -> l in
    match security_domain with Some s -> (k_security_domain, s) :: l | None -> l

  let iattrs' ~backend ?protocol ?port extra =
    let proto = match protocol with Some p -> [ (i_protocol, protocol_to_int p) ] | None -> [] in
    let port = match port with Some n -> [ (i_port, n) ] | None -> [] in
    iattrs ~item_class:class_internet ~backend (proto @ port @ extra)

  let set ?(backend = File_based) ?label ?protocol ?port ?path ?security_domain
      ~server ~account secret =
    let id_s = id ~server ~account ?path ?security_domain () in
    let add_s = Array.of_list (((k_data, secret) :: label_attr label) @ id_s) in
    let st = c_add add_s (iattrs' ~backend ?protocol ?port []) in
    if st = err_success then Ok ()
    else if st = err_duplicate_item then begin
      let q_s = Array.of_list id_s in
      let u_s = Array.of_list ((k_data, secret) :: label_attr label) in
      let st = c_update q_s (iattrs' ~backend ?protocol ?port []) u_s [||] in
      if st = err_success then Ok () else Error (error st)
    end
    else Error (error st)

  let get ?(backend = File_based) ?protocol ?port ?path ?security_domain
      ~server ~account () =
    let q_s = Array.of_list (id ~server ~account ?path ?security_domain ()) in
    let q_i = iattrs' ~backend ?protocol ?port [ (i_return_data, 1); (i_match_limit, 1) ] in
    let st, data = c_copy_data q_s q_i in
    if st = err_success then Ok (Some data)
    else if st = err_item_not_found then Ok None
    else Error (error st)

  let delete ?(backend = File_based) ?protocol ?port ?path ?security_domain
      ~server ~account () =
    let q_s = Array.of_list (id ~server ~account ?path ?security_domain ()) in
    let st = c_delete q_s (iattrs' ~backend ?protocol ?port []) in
    if st = err_success || st = err_item_not_found then Ok ()
    else Error (error st)

  let decode arr =
    { account = Option.value ~default:"" (attr arr k_account);
      server = attr arr k_server;
      path = attr arr k_path;
      security_domain = attr arr k_security_domain;
      label = attr arr k_label }

  let list ?(backend = File_based) ?server ?protocol () =
    let q_s = match server with Some s -> [| (k_server, s) |] | None -> [||] in
    let q_i = iattrs' ~backend ?protocol [ (i_return_attrs, 1); (i_match_limit, 2) ] in
    let st, items = c_copy_attrs q_s q_i in
    if st = err_success then Ok (Array.to_list (Array.map decode items))
    else if st = err_item_not_found then Ok []
    else Error (error st)
end
