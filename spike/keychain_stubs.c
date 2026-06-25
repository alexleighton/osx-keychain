/* Phase 0 spike: hand-written C stubs over Keychain Services (SecItem*).
 *
 * Proves three things end-to-end:
 *   (a) Security.framework + CoreFoundation link from a dune project;
 *   (b) the kSec* const CFStringRef globals are usable (here: directly in C,
 *       which sidesteps the "read const CFStringRef from OCaml" risk);
 *   (c) a full SecItemAdd / SecItemUpdate / SecItemCopyMatching / SecItemDelete
 *       round-trip, including binary-faithful data.
 *
 * Generic-password class only, modern data-protection keychain. Throwaway code
 * — the shipping library will layer this differently (see PLAN.md).
 */

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#include <caml/mlvalues.h>
#include <caml/alloc.h>
#include <caml/memory.h>
#include <string.h>

/* OCaml string (bytes) -> freshly retained CFStringRef (caller releases). */
static CFStringRef cfstr_of_value(value v) {
  return CFStringCreateWithBytes(kCFAllocatorDefault,
                                 (const UInt8 *)Bytes_val(v),
                                 (CFIndex)caml_string_length(v),
                                 kCFStringEncodingUTF8, false);
}

/* Base query: { class = generic password, service, account }. */
static CFMutableDictionaryRef base_query(value service, value account) {
  CFMutableDictionaryRef q =
      CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                                &kCFTypeDictionaryKeyCallBacks,
                                &kCFTypeDictionaryValueCallBacks);
  CFDictionarySetValue(q, kSecClass, kSecClassGenericPassword);
  CFStringRef s = cfstr_of_value(service);
  CFStringRef a = cfstr_of_value(account);
  CFDictionarySetValue(q, kSecAttrService, s);
  CFDictionarySetValue(q, kSecAttrAccount, a);
  CFRelease(s);
  CFRelease(a);
  return q;
}

/* Upsert: add, and on duplicate fall back to update. Returns OSStatus. */
CAMLprim value okc_set(value service, value account, value secret) {
  CAMLparam3(service, account, secret);
  CFMutableDictionaryRef q = base_query(service, account);
  CFDataRef data = CFDataCreate(kCFAllocatorDefault,
                                (const UInt8 *)Bytes_val(secret),
                                (CFIndex)caml_string_length(secret));
  CFDictionarySetValue(q, kSecValueData, data);
  OSStatus st = SecItemAdd(q, NULL);
  if (st == errSecDuplicateItem) {
    CFDictionaryRemoveValue(q, kSecValueData);
    CFMutableDictionaryRef upd =
        CFDictionaryCreateMutable(kCFAllocatorDefault, 1,
                                  &kCFTypeDictionaryKeyCallBacks,
                                  &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(upd, kSecValueData, data);
    st = SecItemUpdate(q, upd);
    CFRelease(upd);
  }
  CFRelease(data);
  CFRelease(q);
  CAMLreturn(Val_int((int)st));
}

/* Returns (OSStatus, data). On not-found / error, data is empty. */
CAMLprim value okc_get(value service, value account) {
  CAMLparam2(service, account);
  CAMLlocal2(res, str);
  CFMutableDictionaryRef q = base_query(service, account);
  CFDictionarySetValue(q, kSecReturnData, kCFBooleanTrue);
  CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitOne);
  CFTypeRef out = NULL;
  OSStatus st = SecItemCopyMatching(q, &out);
  CFRelease(q);
  if (st == errSecSuccess && out != NULL) {
    CFDataRef d = (CFDataRef)out;
    CFIndex len = CFDataGetLength(d);
    str = caml_alloc_string((mlsize_t)len);
    memcpy(Bytes_val(str), CFDataGetBytePtr(d), (size_t)len);
    CFRelease(out);
  } else {
    str = caml_alloc_string(0);
  }
  res = caml_alloc_tuple(2);
  Store_field(res, 0, Val_int((int)st));
  Store_field(res, 1, str);
  CAMLreturn(res);
}

/* Delete the matching item. Returns OSStatus. */
CAMLprim value okc_delete(value service, value account) {
  CAMLparam2(service, account);
  CFMutableDictionaryRef q = base_query(service, account);
  OSStatus st = SecItemDelete(q);
  CFRelease(q);
  CAMLreturn(Val_int((int)st));
}
