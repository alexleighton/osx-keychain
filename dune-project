(lang dune 3.0)

(name osx-keychain)

(generate_opam_files true)

(source
 (github alexleighton/osx-keychain))

(license MIT)

(authors "Alex Leighton <axlelonghorn@gmail.com>")

(maintainers "Alex Leighton <axlelonghorn@gmail.com>")

(package
 (name osx-keychain)
 (synopsis "Typed OCaml bindings to the macOS Keychain")
 (description
  "A native binding to the macOS Keychain Services SecItem* API for storing and\nretrieving generic and internet passwords \226\128\148 a typed alternative to shelling\nout to the security CLI: structured OSStatus errors, exact binary round-trip, no\nsubprocess, and attribute enumeration.\n\nv1 targets the file-based keychain (works on unsigned binaries, no entitlements).\nThe data-protection keychain, biometrics, and iCloud sync require Apple Developer\nprovisioning and are out of scope / experimental.")
 (tags
  ("macos" "keychain" "security" "password" "bindings"))
 (depends
  (ocaml
   (>= "4.14.0"))
  (alcotest :with-test)))
