(** Typed bindings to the macOS Keychain ([SecItem*] API).

    v1 covers generic passwords on the {b file-based} keychain, which works on
    unsigned binaries with no entitlements — the common case for CLI tools and
    daemons, and a structured replacement for shelling out to [security].

    The data-protection keychain ([Data_protection]) is reachable via the
    [?backend] parameter but is {b experimental}: it requires a code-signing
    provisioning profile (an Apple Developer Team ID) to use at all, and an
    unsigned process gets {!Missing_entitlement} or is killed by the kernel. See
    [PLAN.md]. *)

(** Which keychain to target. [File_based] is the default everywhere. *)
type backend =
  | File_based
  | Data_protection  (** experimental — requires provisioning; see above *)

(** Internet-password protocols (the subset mapped to [kSecAttrProtocol*]). *)
type protocol =
  | Http | Https | Ftp | Ftps | Smtp
  | Imap | Imaps | Pop3 | Pop3s | Ssh | Ldap | Ldaps

(** A classification of the most commonly handled [OSStatus] result codes.
    [Other] carries everything else (consult {!field-status}). *)
type error_code =
  | Item_not_found          (** errSecItemNotFound (-25300) *)
  | Duplicate_item          (** errSecDuplicateItem (-25299) *)
  | Auth_failed             (** errSecAuthFailed (-25293) *)
  | User_canceled           (** errSecUserCanceled (-128) *)
  | Interaction_not_allowed (** errSecInteractionNotAllowed (-25308) *)
  | Missing_entitlement     (** errSecMissingEntitlement (-34018) *)
  | Param                   (** errSecParam (-50) *)
  | Other

(** Classify a raw [OSStatus] into an {!error_code}. *)
val code_of_status : int -> error_code

(** A keychain failure: the raw [OSStatus], its classification, and the system's
    human-readable message ([SecCopyErrorMessageString]). *)
type error = {
  status : int;
  code : error_code;
  message : string;
}

(** Generic passwords — keyed by [(service, account)], the primary key the
    keychain uses to decide item identity.

    Secrets are passed and returned as [string]; binary values (including
    embedded NULs) round-trip exactly. Note: OCaml's garbage collector may copy
    or retain these bytes, so the library cannot guarantee a secret is erased
    from memory. *)
module Generic_password : sig
  (** [set ?backend ?label ~service ~account secret] stores [secret], creating
      the item or overwriting an existing one (upsert). Returns [Error] only on
      a real failure, never for "already exists". *)
  val set :
    ?backend:backend ->
    ?label:string ->
    service:string ->
    account:string ->
    string ->
    (unit, error) result

  (** [get ?backend ~service ~account ()] returns [Ok (Some secret)] if present,
      [Ok None] if no such item exists, and [Error] on a real failure. *)
  val get :
    ?backend:backend ->
    service:string ->
    account:string ->
    unit ->
    (string option, error) result

  (** [mem ?backend ~service ~account ()] is [Ok true] iff the item exists,
      without returning its data. *)
  val mem :
    ?backend:backend ->
    service:string ->
    account:string ->
    unit ->
    (bool, error) result

  (** [delete ?backend ~service ~account ()] removes the item. Idempotent:
      deleting a missing item is [Ok ()], not an error. *)
  val delete :
    ?backend:backend ->
    service:string ->
    account:string ->
    unit ->
    (unit, error) result

  (** Identifying attributes of a stored item (no secret data). *)
  type info = {
    service : string;
    account : string;
    label : string option;
  }

  (** [list ?backend ?service ()] returns the attributes of matching items —
      filtered to [service] if given, otherwise every generic-password item.
      Returns metadata only, so it does not prompt for or expose secrets. *)
  val list :
    ?backend:backend ->
    ?service:string ->
    unit ->
    (info list, error) result
end

(** Internet passwords — identified by [(server, account)] plus the optional
    [protocol], [port], [path] and [security_domain] that together form the
    keychain's primary key for this class. Operations that target a specific
    item ([get]/[delete]) must pass the same identifying attributes that [set]
    used, or they will not match. *)
module Internet_password : sig
  (** Store [secret], creating or overwriting (upsert). *)
  val set :
    ?backend:backend ->
    ?label:string ->
    ?protocol:protocol ->
    ?port:int ->
    ?path:string ->
    ?security_domain:string ->
    server:string ->
    account:string ->
    string ->
    (unit, error) result

  (** [Ok (Some secret)] if present, [Ok None] if absent. *)
  val get :
    ?backend:backend ->
    ?protocol:protocol ->
    ?port:int ->
    ?path:string ->
    ?security_domain:string ->
    server:string ->
    account:string ->
    unit ->
    (string option, error) result

  (** Remove the item; idempotent (missing item is [Ok ()]). *)
  val delete :
    ?backend:backend ->
    ?protocol:protocol ->
    ?port:int ->
    ?path:string ->
    ?security_domain:string ->
    server:string ->
    account:string ->
    unit ->
    (unit, error) result

  (** Identifying attributes of a stored item (no secret data). [server] etc.
      are optional because the keychain may not record every attribute. *)
  type info = {
    account : string;
    server : string option;
    path : string option;
    security_domain : string option;
    label : string option;
  }

  (** [list ?backend ?server ?protocol ()] returns matching items' attributes,
      optionally filtered by [server] and/or [protocol]. Metadata only. *)
  val list :
    ?backend:backend ->
    ?server:string ->
    ?protocol:protocol ->
    unit ->
    (info list, error) result
end
