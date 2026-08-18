# CrossVul Fix Pair: Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') in c
**Pair ID:** 4617_3
**Vulnerability Class:** HTTP Request Smuggling
**CWE:** CWE-444
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4617_3`)

## Vulnerability Information & PoC

## Description
Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') - HTTP requests or responses (messages) can be malformed or unexpected in ways that cause web servers or clients to interpret the messages in different ways than intermediary HTTP agents such as load...

## Vulnerable Code
```c
Lines 9-49 of the vulnerable file.

#include "http.h"

#define BUCKET_SIZE	1024
#define BUCKET_MASK	1023
#define MAX_KEY_UNIQ	9

typedef struct _slot {
    struct _slot	*next;
    const char		*key;
    uint64_t		hash;
    int			klen;
} *Slot;

typedef struct _cache {
    Slot		buckets[BUCKET_SIZE];
} *Cache;

struct _cache		key_cache;

// The rack spec indicates the characters (),/:;<=>?@[]{} are invalid which
// clearly is not consisten with RFC7230 so stick with the RFC.
static char		header_value_chars[256] = "\
xxxxxxxxxxoxxxxxxxxxxxxxxxxxxxxx\
oooooooooooooooooooooooooooooooo\
oooooooooooooooooooooooooooooooo\
ooooooooooooooooooooooooooooooox\
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

static const char	*header_keys[] = {
    "A-IM",
    "ALPN",
    "ARC-Authentication-Results",
    "ARC-Message-Signature",
    "ARC-Seal",
    "Accept",
    "Accept-Additions",
    "Accept-Charset",
    "Accept-Datetime",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -26,7 +26,7 @@
 struct _cache		key_cache;
 
 // The rack spec indicates the characters (),/:;<=>?@[]{} are invalid which
-// clearly is not consisten with RFC7230 so stick with the RFC.
+// clearly is not consistent with RFC7230 so stick with the RFC.
 static char		header_value_chars[256] = "\
 xxxxxxxxxxoxxxxxxxxxxxxxxxxxxxxx\
 oooooooooooooooooooooooooooooooo\
@@ -49,7 +49,6 @@
     "Accept-Datetime",
     "Accept-Encoding",
     "Accept-Features",
-    "Accept-Language",
     "Accept-Language",
     "Accept-Patch",
     "Accept-Post",
@@ -73,7 +72,6 @@
     "Apply-To-Redirect-Ref",
     "Approved",
     "Archive",
-    "Archived-At",
     "Archived-At",
     "Article-Names",
     "Article-Updates",
@@ -99,35 +97,26 @@
     "Cc",
     "Close",
     "Comments",
-    "Comments",
     "Compliance",
     "Connection",
     "Content-Alternative",
     "Content-Base",
-    "Content-Base",
     "Content-Description",
-    "Content-Disposition",
     "Content-Disposition",
     "Content-Duration",
     "Content-Encoding",
     "Content-ID",
-    "Content-ID",
     "Content-Identifier",
-    "Content-Language",
     "Content-Language",
     "Content-Length",
     "Content-Location",
-    "Content-Location",
-    "Content-MD5",
     "Content-MD5",
     "Content-Range",
     "Content-Return",
     "Content-Script-Type",
     "Content-Style-Type",
     "Content-Transfer-Encoding",
-    "Content-Transfer-Encoding",
     "Content-Translation-Type",
-    "Content-Type",
     "Content-Type",
     "Content-Version",
     "Content-features",
@@ -141,8 +130,7 @@
     "DAV",
     "DKIM-Signature",
     "DL-Expansion-History",
-    "Date",
-    "Date",
+    "DNT",
     "Date",
     "Date-Received",
     "Default-Style",
@@ -182,7 +170,6 @@
     "Downgraded-Sender",
     "Downgraded-To",
     "EDIINT-Features",
-    "EDIINT-Features",
     "ETag",
     "Eesst-Version",
     "Encoding",
@@ -190,16 +177,13 @@
     "Errors-To",
     "Expect",
     "Expires",
-    "Expires",
-    "Expires",
     "Expiry-Date",
     "Ext",
     "Followup-To",
     "Form-Sub",
     "Forwarded",
     "From",
-    "From",
-    "From",
+    "Front-End-Https",
     "Generate-Delivery-Report",
     "GetProfile",
     "HTTP2-Settings",
@@ -219,9 +203,7 @@
     "Injection-Date",
     "Injection-Info",
     "Jabber-ID",
-    "Jabber-ID",
     "Keep-Alive",
-    "Keywords",
     "Keywords",
     "Label",
     "Language",
@@ -239,7 +221,6 @@
     "List-Unsubscribe-Post",
     "Location",
     "Lock-Token",
-    "MIME-Version",
     "MIME-Version",
     "MMHS-Acp127-Message-Identifier",
     "MMHS-Authorizing-Users",
@@ -262,8 +243,6 @@
     "Memento-Datetime",
     "Message-Context",
     "Message-ID",
-    "Message-ID",
-    "Message-ID",
     "Message-Type",
     "Meter",
     "Method-Check",
@@ -279,7 +258,6 @@
     "Optional-WWW-Authenticate",
     "Ordering-Type",
     "Organization",
-    "Organization",
     "Origin",
     "Original-Encoded-Information-Types",
     "Original-From",
@@ -291,7 +269,6 @@
     "Overwrite",
     "P3P",
     "PEP",
-    "PICS-Label",
     "PICS-Label",
     "Path",
     "Pep-Info",
@@ -311,6 +288,7 @@
     "Proxy-Authenticate",
     "Proxy-Authentication-Info",
     "Proxy-Authorization",
+    "Proxy-Connection",
     "Proxy-Features",
     "Proxy-Instruction",
     "Public",
@@ -321,12 +299,10 @@
     "Received-SPF",
     "Redirect-Ref",
     "References",
-    "References",
     "Referer",
     "Referer-Root",
     "Relay-Version",
     "Reply-By",
-    "Reply-To",
     "Reply-To",
     "Require-Recipient-Valid-Since",
     "Resent-Bcc",
@@ -345,6 +321,7 @@
     "SIO-Label-History",
     "SLUG",
     "Safe",
+    "Save-Data",
     "Schedule-Reply",
     "Schedule-Tag",
     "Sec-WebSocket-Accept",
@@ -367,10 +344,8 @@
     "Strict-Transport-Security",
     "SubOK",
     "Subject",
-    "Subject",
     "Subst",
     "Summary",
-    "Supersedes",
     "Supersedes",
     "Surrogate-Capability",
     "Surrogate-Control",
@@ -390,8 +365,8 @@
     "UA-Windowpixels",
     "URI",
     "Upgrade",
+    "Upgrade-Insecure-Requests",
     "Urgency",
-    "User-Agent",
     "User-Agent",
     "VBR-Info",
     "Variant-Vary",
@@ -401,22 +376,32 @@
     "WWW-Authenticate",
     "Want-Digest",
     "Warning",
-    "X-Archived-At",
+    "X-ATT-DeviceId",
     "X-Archived-At",
     "X-Content-Type-Options",
+    "X-Correlation-ID",
+    "X-Csrf-Token",
     "X-Device-Accept",
     "X-Device-Accept-Charset",
     "X-Device-Accept-Encoding",
     "X-Device-Accept-Language",
     "X-Device-User-Agent",
+    "X-Forwarded-For",
+    "X-Forwarded-Host",
+    "X-Forwarded-Proto",
     "X-Frame-Options",
+    "X-Http-Method-Override",
     "X-Mittente",
     "X-PGP-Sig",
+    "X-Request-ID",
+    "X-Requested-With",
     "X-Ricevuta",
     "X-Riferimento-Message-ID",
     "X-TipoRicevuta",
     "X-Trasporto",
+    "X-UIDH",
     "X-VerificaSicurezza",
+    "X-Wap-Profile",
     "X-XSS-Protection",
     "X400-Content-Identifier",
     "X400-Content-Return",
@@ -469,7 +454,7 @@
     int64_t	h = calc_hash(key, &len);
     Slot	*bucket = get_bucketp(h);
     Slot	s;
-    
+
     if (NULL != (s = (Slot)AGOO_MALLOC(sizeof(struct _slot)))) {
 	s->hash = h;
 	s->klen = len;
@@ -482,7 +467,7 @@
 void
 agoo_http_init() {
     const char	**kp = header_keys;
-    
+
     memset(&key_cache, 0, sizeof(struct _cache));
     for (; NULL != *kp; kp++) {
 	key_set(*kp);
@@ -550,7 +535,7 @@
 const char*
 agoo_http_code_message(int code) {
     const char	*msg = "";
-    
+
     switch (code) {
     case 100:	msg = "Continue";				break;
     case 101:	msg = "Switching Protocols";			break;
```
