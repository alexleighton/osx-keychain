external dp_probe : bool -> string -> int = "okc_dp_probe"

let name = function
  | 0 -> "errSecSuccess"
  | -25291 -> "errSecNotAvailable"
  | -25300 -> "errSecItemNotFound"
  | -34018 -> "errSecMissingEntitlement"
  | -50 -> "errSecParam"
  | n -> Printf.sprintf "OSStatus(%d)" n

let () =
  List.iter
    (fun (dp, ag, descr) ->
      Printf.printf "%-46s -> %s\n" descr (name (dp_probe dp ag)))
    [ (false, "", "file-based (no DP flag)");
      (true, "", "data-protection (DP flag, no access group)");
      (true, "com.osx-keychain.test",
       "data-protection + explicit access group") ]
