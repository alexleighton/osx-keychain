(** Typed bindings to the macOS Keychain ([SecItem*] API).

    v1 covers generic passwords on the {b file-based} keychain, which works on
    unsigned binaries with no entitlements — the common case for CLI tools and
    daemons, and a structured replacement for shelling out to [security].

    The data-protection keychain ([Data_protection]) is reachable via the
    [?backend] parameter but is {b experimental}: it requires a code-signing
    provisioning profile (an Apple Developer Team ID) to use at all, and an
    unsigned process gets {!Missing_entitlement} or is killed by the kernel. See
    [reference/keychain-notes.md] (§1, §3) for the full rationale. *)

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
    human-readable message ([SecCopyErrorMessageString]).

    Note on which codes you actually see here: this library folds the "expected"
    statuses into successes — a missing item is [Ok None] (from [get]) or [Ok ()]
    (from [delete]), and a duplicate on [set] is resolved by updating in place —
    so an [Error] generally carries a {e genuine} failure ([Auth_failed],
    [Interaction_not_allowed], [Missing_entitlement], [Param], …). The exception
    is a rare TOCTOU race: if an item is deleted between [set]'s add (which sees
    a duplicate) and its follow-up update, you can get [Error] with
    [code = Item_not_found]. *)
type error = {
  status : int;
  code : error_code;
  message : string;
}

(** A one-line rendering, e.g. ["Auth_failed (OSStatus -25293): ..."]. *)
val to_string : error -> string

(** Overwrite a buffer with zero bytes — for wiping a secret after use (see
    {!Generic_password.get_bytes}). Best-effort only: OCaml's garbage collector
    may have made transient copies this cannot reach, and the OS keeps the
    secret in its own memory regardless, so this is hygiene, not a guarantee. *)
val wipe : bytes -> unit

(** Generic passwords — keyed by [(service, account)], the primary key the
    keychain uses to decide item identity.

    Secrets are passed and returned as [string]; binary values (including
    embedded NULs) round-trip exactly. Note: OCaml's garbage collector may copy
    or retain these bytes, so the library cannot guarantee a secret is erased
    from memory. *)
module Generic_password : sig
  (** [set ?backend ?label ~service ~account secret] stores [secret], creating
      the item or overwriting an existing one (upsert). Returns [Error] only on
      a real failure, never for "already exists".

      {b Framework:} [SecItemAdd] on a [kSecClassGenericPassword] item, falling
      back to [SecItemUpdate] when it reports [errSecDuplicateItem].
      {b CLI:} [security add-generic-password -U -s SERVICE -a ACCOUNT -w SECRET]
      (the [-w] secret is visible to [ps]; this call passes it out-of-band). *)
  val set :
    ?backend:backend ->
    ?label:string ->
    service:string ->
    account:string ->
    string ->
    (unit, error) result

  (** [get ?backend ~service ~account ()] returns [Ok (Some secret)] if present,
      [Ok None] if no such item exists, and [Error] on a real failure.

      {b Framework:} [SecItemCopyMatching] with [kSecReturnData].
      {b CLI:} [security find-generic-password -s SERVICE -a ACCOUNT -w] (which
      exits non-zero on a miss, where this returns the typed [Ok None]). *)
  val get :
    ?backend:backend ->
    service:string ->
    account:string ->
    unit ->
    (string option, error) result

  (** As {!get}, but returns the secret as a caller-owned mutable [bytes] that
      can be {!wipe}d when no longer needed.

      {b Framework:} [SecItemCopyMatching] with [kSecReturnData] (as {!get}).
      {b CLI:} [security find-generic-password -s SERVICE -a ACCOUNT -w] — but
      the CLI writes the secret to stdout, leaving nothing to {!wipe}. *)
  val get_bytes :
    ?backend:backend ->
    service:string ->
    account:string ->
    unit ->
    (bytes option, error) result

  (** [with_secret ?backend ~service ~account f] fetches the secret, runs [f] on
      a [bytes] buffer the library owns, and {!wipe}s that buffer before
      returning — even if [f] raises (the exception propagates after the wipe).

      [f] runs only when the item exists: the result is [Ok (Some (f buf))] if
      present, [Ok None] if absent (so [f] is never called), and [Error] on a
      real failure.

      {b Do not let the buffer, or a copy of its bytes, escape [f]:} once
      [with_secret] returns the buffer is zeroed, and — as with {!wipe} — the
      garbage collector may still hold transient copies this cannot reach.

      {b Framework:} [SecItemCopyMatching] with [kSecReturnData] (as {!get_bytes}).
      {b CLI:} no equivalent — once [security find-generic-password -w] prints
      the secret to stdout there is nothing to scrub. *)
  val with_secret :
    ?backend:backend ->
    service:string ->
    account:string ->
    (bytes -> 'a) ->
    ('a option, error) result

  (** [mem ?backend ~service ~account ()] is [Ok true] iff the item exists,
      without returning its data.

      {b Framework:} [SecItemCopyMatching] without [kSecReturnData].
      {b CLI:} [security find-generic-password -s SERVICE -a ACCOUNT] (no [-w]);
      existence is the exit code. *)
  val mem :
    ?backend:backend ->
    service:string ->
    account:string ->
    unit ->
    (bool, error) result

  (** [delete ?backend ~service ~account ()] removes the item. Idempotent:
      deleting a missing item is [Ok ()], not an error.

      {b Framework:} [SecItemDelete].
      {b CLI:} [security delete-generic-password -s SERVICE -a ACCOUNT] (which
      exits non-zero on a miss, where this returns [Ok ()]). *)
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
      Returns metadata only, so it does not prompt for or expose secrets.

      {b Framework:} [SecItemCopyMatching] with [kSecReturnAttributes] and
      [kSecMatchLimitAll].
      {b CLI:} no per-service equivalent — the nearest is [security dump-keychain],
      which dumps every item and prompts repeatedly. *)
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
  (** Store [secret], creating or overwriting (upsert).

      {b Framework:} [SecItemAdd] on a [kSecClassInternetPassword] item, falling
      back to [SecItemUpdate] on [errSecDuplicateItem]; [protocol]/[port] map to
      [kSecAttrProtocol]/[kSecAttrPort].
      {b CLI:} [security add-internet-password -U -s SERVER -a ACCOUNT -r imps
      -P 993 -w SECRET] ([-r] is the 4-char protocol code: imps = IMAPS, …). *)
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

  (** [Ok (Some secret)] if present, [Ok None] if absent.

      {b Framework:} [SecItemCopyMatching] with [kSecReturnData].
      {b CLI:} [security find-internet-password -s SERVER -a ACCOUNT -r imps
      -P 993 -w]. *)
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

  (** As {!get}, but returns the secret as a caller-owned mutable [bytes].

      {b Framework:} [SecItemCopyMatching] with [kSecReturnData] (as {!get}).
      {b CLI:} [security find-internet-password … -w] — but the CLI writes the
      secret to stdout, leaving nothing to {!wipe}. *)
  val get_bytes :
    ?backend:backend ->
    ?protocol:protocol ->
    ?port:int ->
    ?path:string ->
    ?security_domain:string ->
    server:string ->
    account:string ->
    unit ->
    (bytes option, error) result

  (** As {!Generic_password.with_secret}: runs [f] on a library-owned [bytes]
      buffer and {!wipe}s it before returning (even if [f] raises). [f] runs
      only when the item exists; the same escape caveat applies.

      {b Framework:} [SecItemCopyMatching] with [kSecReturnData] (as {!get_bytes}).
      {b CLI:} no equivalent — [security find-internet-password -w] prints the
      secret to stdout, leaving nothing to scrub. *)
  val with_secret :
    ?backend:backend ->
    ?protocol:protocol ->
    ?port:int ->
    ?path:string ->
    ?security_domain:string ->
    server:string ->
    account:string ->
    (bytes -> 'a) ->
    ('a option, error) result

  (** Remove the item; idempotent (missing item is [Ok ()]).

      {b Framework:} [SecItemDelete].
      {b CLI:} [security delete-internet-password -s SERVER -a ACCOUNT -r imps
      -P 993] (exits non-zero on a miss, where this returns [Ok ()]). *)
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
      optionally filtered by [server] and/or [protocol]. Metadata only.

      {b Framework:} [SecItemCopyMatching] with [kSecReturnAttributes] and
      [kSecMatchLimitAll].
      {b CLI:} no filtered equivalent — the nearest is [security dump-keychain],
      which dumps every item and prompts repeatedly. *)
  val list :
    ?backend:backend ->
    ?server:string ->
    ?protocol:protocol ->
    unit ->
    (info list, error) result
end
