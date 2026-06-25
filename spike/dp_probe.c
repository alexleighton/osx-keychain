/* Phase 0.5 probe: can we reach the data-protection keychain, and under what
 * signing? Adds a generic password with kSecUseDataProtectionKeychain and
 * reports the OSStatus (errSecMissingEntitlement = -34018 means "blocked").
 * Best-effort cleanup after. Throwaway. */

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <caml/mlvalues.h>
#include <caml/memory.h>

CAMLprim value okc_dp_probe(value use_dp, value access_group) {
  CAMLparam2(use_dp, access_group);
  CFMutableDictionaryRef q =
      CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                                &kCFTypeDictionaryKeyCallBacks,
                                &kCFTypeDictionaryValueCallBacks);
  CFDictionarySetValue(q, kSecClass, kSecClassGenericPassword);
  CFDictionarySetValue(q, kSecAttrService, CFSTR("com.osx-keychain.dpprobe"));
  CFDictionarySetValue(q, kSecAttrAccount, CFSTR("probe"));
  if (Bool_val(use_dp))
    CFDictionarySetValue(q, kSecUseDataProtectionKeychain, kCFBooleanTrue);
  if (caml_string_length(access_group) > 0) {
    CFStringRef ag = CFStringCreateWithCString(kCFAllocatorDefault,
        String_val(access_group), kCFStringEncodingUTF8);
    CFDictionarySetValue(q, kSecAttrAccessGroup, ag);
    CFRelease(ag);
  }
  const UInt8 payload[4] = {1, 2, 3, 4};
  CFDataRef data = CFDataCreate(kCFAllocatorDefault, payload, 4);
  CFDictionarySetValue(q, kSecValueData, data);

  OSStatus st = SecItemAdd(q, NULL);

  CFDictionaryRemoveValue(q, kSecValueData);  /* best-effort cleanup */
  SecItemDelete(q);
  CFRelease(data);
  CFRelease(q);
  CAMLreturn(Val_int((int)st));
}
