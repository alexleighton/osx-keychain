/* C stubs for osx-keychain — the only code that touches CoreFoundation and the
 * kSec* constants. The OCaml side hands us two int-tagged arrays describing the
 * attributes of a query/item; we translate tags -> kSec* keys, build the
 * CFDictionary, call the SecItem* function, and hand back plain OCaml values.
 *
 * Boundary contract (tags MUST stay in sync with osx_keychain.ml):
 *
 *   string-valued attrs:  (int tag, string value) array
 *     1  K_SERVICE  -> kSecAttrService   (CFString)
 *     2  K_ACCOUNT  -> kSecAttrAccount   (CFString)
 *     3  K_LABEL    -> kSecAttrLabel     (CFString)
 *     4  K_DATA     -> kSecValueData     (CFData — binary, may contain NULs)
 *
 *   int/bool-valued attrs: (int tag, int value) array
 *     100 I_CLASS        -> kSecClass; value 0 = generic password
 *     101 I_MATCH_LIMIT  -> kSecMatchLimit; 1 = One, 2 = All
 *     102 I_RETURN_DATA  -> kSecReturnData; 0/1 boolean
 *     103 I_USE_DP       -> kSecUseDataProtectionKeychain; 0/1 boolean
 *
 * Every SecItem* call releases the OCaml runtime lock: these calls IPC to
 * securityd and (for access-control items, later) can block on a UI prompt, so
 * we must not freeze the whole runtime. While the lock is released we touch
 * only CoreFoundation objects, never OCaml values.
 */

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#include <caml/mlvalues.h>
#include <caml/alloc.h>
#include <caml/memory.h>
#include <caml/threads.h>
#include <stdlib.h>
#include <string.h>

#define K_SERVICE 1
#define K_ACCOUNT 2
#define K_LABEL 3
#define K_DATA 4

#define I_CLASS 100
#define I_MATCH_LIMIT 101
#define I_RETURN_DATA 102
#define I_USE_DP 103

static CFStringRef string_key(int tag) {
  switch (tag) {
    case K_SERVICE: return kSecAttrService;
    case K_ACCOUNT: return kSecAttrAccount;
    case K_LABEL:   return kSecAttrLabel;
    case K_DATA:    return kSecValueData;
    default:        return NULL;
  }
}

/* Reads OCaml values — caller must hold the runtime lock. Allocates no OCaml. */
static void add_string_attrs(CFMutableDictionaryRef q, value sattrs) {
  mlsize_t n = Wosize_val(sattrs);
  for (mlsize_t i = 0; i < n; i++) {
    value pair = Field(sattrs, i);
    int tag = Int_val(Field(pair, 0));
    value s = Field(pair, 1);
    const UInt8 *bytes = (const UInt8 *)String_val(s);
    CFIndex len = (CFIndex)caml_string_length(s);
    CFStringRef key = string_key(tag);
    if (key == NULL) continue;
    if (tag == K_DATA) {
      CFDataRef d = CFDataCreate(kCFAllocatorDefault, bytes, len);
      CFDictionarySetValue(q, key, d);
      CFRelease(d);
    } else {
      CFStringRef v = CFStringCreateWithBytes(kCFAllocatorDefault, bytes, len,
                                              kCFStringEncodingUTF8, false);
      CFDictionarySetValue(q, key, v);
      CFRelease(v);
    }
  }
}

static void add_int_attrs(CFMutableDictionaryRef q, value iattrs) {
  mlsize_t n = Wosize_val(iattrs);
  for (mlsize_t i = 0; i < n; i++) {
    value pair = Field(iattrs, i);
    int tag = Int_val(Field(pair, 0));
    int v = Int_val(Field(pair, 1));
    switch (tag) {
      case I_CLASS:
        CFDictionarySetValue(q, kSecClass, kSecClassGenericPassword);
        break;
      case I_MATCH_LIMIT:
        CFDictionarySetValue(q, kSecMatchLimit,
                             v == 2 ? kSecMatchLimitAll : kSecMatchLimitOne);
        break;
      case I_RETURN_DATA:
        CFDictionarySetValue(q, kSecReturnData,
                             v ? kCFBooleanTrue : kCFBooleanFalse);
        break;
      case I_USE_DP:
        CFDictionarySetValue(q, kSecUseDataProtectionKeychain,
                             v ? kCFBooleanTrue : kCFBooleanFalse);
        break;
      default:
        break;
    }
  }
}

static CFMutableDictionaryRef build_dict(value sattrs, value iattrs) {
  CFMutableDictionaryRef q =
      CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                                &kCFTypeDictionaryKeyCallBacks,
                                &kCFTypeDictionaryValueCallBacks);
  add_string_attrs(q, sattrs);
  add_int_attrs(q, iattrs);
  return q;
}

CAMLprim value osxkc_add(value sattrs, value iattrs) {
  CAMLparam2(sattrs, iattrs);
  CFMutableDictionaryRef q = build_dict(sattrs, iattrs);
  OSStatus st;
  caml_release_runtime_system();
  st = SecItemAdd(q, NULL);
  caml_acquire_runtime_system();
  CFRelease(q);
  CAMLreturn(Val_int((int)st));
}

CAMLprim value osxkc_copy_data(value sattrs, value iattrs) {
  CAMLparam2(sattrs, iattrs);
  CAMLlocal2(res, str);
  CFMutableDictionaryRef q = build_dict(sattrs, iattrs);
  CFTypeRef out = NULL;
  OSStatus st;
  caml_release_runtime_system();
  st = SecItemCopyMatching(q, &out);
  caml_acquire_runtime_system();
  CFRelease(q);
  if (st == errSecSuccess && out != NULL && CFGetTypeID(out) == CFDataGetTypeID()) {
    CFDataRef d = (CFDataRef)out;
    CFIndex len = CFDataGetLength(d);
    str = caml_alloc_string((mlsize_t)len);
    memcpy(Bytes_val(str), CFDataGetBytePtr(d), (size_t)len);
  } else {
    str = caml_alloc_string(0);
  }
  if (out != NULL) CFRelease(out);
  res = caml_alloc_tuple(2);
  Store_field(res, 0, Val_int((int)st));
  Store_field(res, 1, str);
  CAMLreturn(res);
}

CAMLprim value osxkc_update(value qs, value qi, value us, value ui) {
  CAMLparam4(qs, qi, us, ui);
  CFMutableDictionaryRef q = build_dict(qs, qi);
  CFMutableDictionaryRef u = build_dict(us, ui);
  OSStatus st;
  caml_release_runtime_system();
  st = SecItemUpdate(q, u);
  caml_acquire_runtime_system();
  CFRelease(q);
  CFRelease(u);
  CAMLreturn(Val_int((int)st));
}

CAMLprim value osxkc_delete(value sattrs, value iattrs) {
  CAMLparam2(sattrs, iattrs);
  CFMutableDictionaryRef q = build_dict(sattrs, iattrs);
  OSStatus st;
  caml_release_runtime_system();
  st = SecItemDelete(q);
  caml_acquire_runtime_system();
  CFRelease(q);
  CAMLreturn(Val_int((int)st));
}

CAMLprim value osxkc_error_message(value status) {
  CAMLparam1(status);
  CAMLlocal1(str);
  CFStringRef msg = SecCopyErrorMessageString((OSStatus)Int_val(status), NULL);
  if (msg != NULL) {
    CFIndex maxlen =
        CFStringGetMaximumSizeForEncoding(CFStringGetLength(msg),
                                          kCFStringEncodingUTF8) + 1;
    char *buf = malloc((size_t)maxlen);
    if (buf != NULL &&
        CFStringGetCString(msg, buf, maxlen, kCFStringEncodingUTF8)) {
      str = caml_copy_string(buf);
    } else {
      str = caml_copy_string("");
    }
    free(buf);
    CFRelease(msg);
  } else {
    str = caml_copy_string("");
  }
  CAMLreturn(str);
}
