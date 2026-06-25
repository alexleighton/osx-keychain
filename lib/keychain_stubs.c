/* C stubs for osx-keychain — the only code that touches CoreFoundation and the
 * kSec* constants. The OCaml side hands us two int-tagged arrays describing the
 * attributes of a query/item; we translate tags -> kSec* keys, build the
 * CFDictionary, call the SecItem* function, and hand back plain OCaml values.
 *
 * Boundary contract (tags MUST stay in sync with osx_keychain.ml):
 *
 *   string-valued attrs:  (int tag, string value) array
 *     1  K_SERVICE          -> kSecAttrService        (CFString)
 *     2  K_ACCOUNT          -> kSecAttrAccount        (CFString)
 *     3  K_LABEL            -> kSecAttrLabel          (CFString)
 *     4  K_DATA             -> kSecValueData          (CFData — binary)
 *     5  K_SERVER           -> kSecAttrServer         (CFString)
 *     6  K_PATH             -> kSecAttrPath           (CFString)
 *     7  K_SECURITY_DOMAIN  -> kSecAttrSecurityDomain (CFString)
 *
 *   int/bool-valued attrs: (int tag, int value) array
 *     100 I_CLASS         -> kSecClass; 0 = generic, 1 = internet password
 *     101 I_MATCH_LIMIT   -> kSecMatchLimit; 1 = One, 2 = All
 *     102 I_RETURN_DATA   -> kSecReturnData; 0/1 boolean
 *     103 I_USE_DP        -> kSecUseDataProtectionKeychain; 0/1 boolean
 *     104 I_RETURN_ATTRS  -> kSecReturnAttributes; 0/1 boolean
 *     105 I_PROTOCOL      -> kSecAttrProtocol; value selects a protocol const
 *     106 I_PORT          -> kSecAttrPort (CFNumber)
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
#define K_SERVER 5
#define K_PATH 6
#define K_SECURITY_DOMAIN 7

#define I_CLASS 100
#define I_MATCH_LIMIT 101
#define I_RETURN_DATA 102
#define I_USE_DP 103
#define I_RETURN_ATTRS 104
#define I_PROTOCOL 105
#define I_PORT 106

static CFStringRef string_key(int tag) {
  switch (tag) {
    case K_SERVICE:         return kSecAttrService;
    case K_ACCOUNT:         return kSecAttrAccount;
    case K_LABEL:           return kSecAttrLabel;
    case K_DATA:            return kSecValueData;
    case K_SERVER:          return kSecAttrServer;
    case K_PATH:            return kSecAttrPath;
    case K_SECURITY_DOMAIN: return kSecAttrSecurityDomain;
    default:                return NULL;
  }
}

/* Maps a protocol tag value to a kSecAttrProtocol* constant. Keep in sync with
   the `protocol` variant / protocol_to_int in osx_keychain.ml. */
static CFStringRef protocol_const(int v) {
  switch (v) {
    case 1:  return kSecAttrProtocolHTTP;
    case 2:  return kSecAttrProtocolHTTPS;
    case 3:  return kSecAttrProtocolFTP;
    case 4:  return kSecAttrProtocolFTPS;
    case 5:  return kSecAttrProtocolSMTP;
    case 6:  return kSecAttrProtocolIMAP;
    case 7:  return kSecAttrProtocolIMAPS;
    case 8:  return kSecAttrProtocolPOP3;
    case 9:  return kSecAttrProtocolPOP3S;
    case 10: return kSecAttrProtocolSSH;
    case 11: return kSecAttrProtocolLDAP;
    case 12: return kSecAttrProtocolLDAPS;
    default: return kSecAttrProtocolHTTPS;
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
        CFDictionarySetValue(q, kSecClass,
                             v == 1 ? kSecClassInternetPassword
                                    : kSecClassGenericPassword);
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
      case I_RETURN_ATTRS:
        CFDictionarySetValue(q, kSecReturnAttributes,
                             v ? kCFBooleanTrue : kCFBooleanFalse);
        break;
      case I_PROTOCOL:
        CFDictionarySetValue(q, kSecAttrProtocol, protocol_const(v));
        break;
      case I_PORT: {
        CFNumberRef n = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &v);
        CFDictionarySetValue(q, kSecAttrPort, n);
        CFRelease(n);
        break;
      }
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

/* CFString -> fresh OCaml string (UTF-8). Allocates OCaml; lock must be held. */
static value cfstring_to_ml(CFStringRef s) {
  CAMLparam0();
  CAMLlocal1(out);
  CFIndex maxlen =
      CFStringGetMaximumSizeForEncoding(CFStringGetLength(s),
                                        kCFStringEncodingUTF8) + 1;
  char *buf = malloc((size_t)maxlen);
  if (buf != NULL && CFStringGetCString(s, buf, maxlen, kCFStringEncodingUTF8)) {
    out = caml_copy_string(buf);
  } else {
    out = caml_copy_string("");
  }
  free(buf);
  CAMLreturn(out);
}

/* Extract the string-valued identifying attributes present in a result dict,
   returned as a (int tag, string value) array (same tag scheme as input). */
static value extract_string_attrs(CFDictionaryRef d) {
  CAMLparam0();
  CAMLlocal3(arr, pair, str);
  const struct { int tag; CFStringRef key; } map[] = {
    { K_SERVICE, kSecAttrService },
    { K_ACCOUNT, kSecAttrAccount },
    { K_LABEL, kSecAttrLabel },
    { K_SERVER, kSecAttrServer },
    { K_PATH, kSecAttrPath },
    { K_SECURITY_DOMAIN, kSecAttrSecurityDomain },
  };
  const int nmap = (int)(sizeof(map) / sizeof(map[0]));
  int present[8];
  int np = 0;
  for (int i = 0; i < nmap; i++) {
    CFTypeRef v = CFDictionaryGetValue(d, map[i].key);
    if (v != NULL && CFGetTypeID(v) == CFStringGetTypeID()) present[np++] = i;
  }
  arr = (np == 0) ? Atom(0) : caml_alloc_tuple(np);
  for (int j = 0; j < np; j++) {
    int i = present[j];
    CFStringRef v = (CFStringRef)CFDictionaryGetValue(d, map[i].key);
    str = cfstring_to_ml(v);
    pair = caml_alloc_tuple(2);
    Store_field(pair, 0, Val_int(map[i].tag));
    Store_field(pair, 1, str);
    Store_field(arr, j, pair);
  }
  CAMLreturn(arr);
}

/* Enumerate matching items' attributes (no secret data). Expects the caller to
   have set return-attributes + match-limit-all via tags. Returns
   (OSStatus, (int * string) array array). */
CAMLprim value osxkc_copy_attrs(value sattrs, value iattrs) {
  CAMLparam2(sattrs, iattrs);
  CAMLlocal2(res, items);
  CFMutableDictionaryRef q = build_dict(sattrs, iattrs);
  CFTypeRef out = NULL;
  OSStatus st;
  caml_release_runtime_system();
  st = SecItemCopyMatching(q, &out);
  caml_acquire_runtime_system();
  CFRelease(q);
  items = Atom(0);
  if (st == errSecSuccess && out != NULL &&
      CFGetTypeID(out) == CFArrayGetTypeID()) {
    CFArrayRef a = (CFArrayRef)out;
    CFIndex count = CFArrayGetCount(a);
    items = (count == 0) ? Atom(0) : caml_alloc_tuple((mlsize_t)count);
    for (CFIndex i = 0; i < count; i++) {
      CFDictionaryRef d = (CFDictionaryRef)CFArrayGetValueAtIndex(a, i);
      Store_field(items, i, extract_string_attrs(d));
    }
  }
  if (out != NULL) CFRelease(out);
  res = caml_alloc_tuple(2);
  Store_field(res, 0, Val_int((int)st));
  Store_field(res, 1, items);
  CAMLreturn(res);
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
