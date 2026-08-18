# CrossVul Fix Pair: Improper Input Validation in cpp
**Pair ID:** 1749_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1749_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```cpp
Lines 185-225 of the vulnerable file.

	SKC_LOG_EVENT_FROM_STATIC(self, Controller, client, "sendBodyToAppWhenAppSinkIdle");

	channel->setConsumedCallback(NULL);
	if (channel->acceptingInput()) {
		self->sendBodyToApp(client, req);
		if (!req->ended()) {
			req->appSource.startReading();
		}
	} else {
		// req->appSink.feed() encountered an error while writing to the
		// application socket. But we don't care about that; we just care that
		// ForwardResponse.cpp will now forward the response data and end the
		// request when it's done.
		UPDATE_TRACE_POINT();
		assert(!req->appSink.ended());
		assert(req->appSink.hasError());
		self->logAppSocketWriteError(client, req->appSink.getErrcode());
		req->state = Request::WAITING_FOR_APP_OUTPUT;
		req->appSource.startReading();
	}
}

static void
httpHeaderToScgiUpperCase(unsigned char *data, unsigned int size) {
	static const boost::uint8_t toUpperMap[256] = {
		'\0', 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, '\t',
		'\n', 0x0b, 0x0c, '\r', 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
		0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
		0x1e, 0x1f,  ' ',  '!',  '"',  '#',  '$',  '%',  '&', '\'',
		 '(',  ')',  '*',  '+',  ',',  '_',  '.',  '/',  '0',  '1',
		 '2',  '3',  '4',  '5',  '6',  '7',  '8',  '9',  ':',  ';',
		 '<',  '=',  '>',  '?',  '@',  'A',  'B',  'C',  'D',  'E',
		 'F',  'G',  'H',  'I',  'J',  'K',  'L',  'M',  'N',  'O',
		 'P',  'Q',  'R',  'S',  'T',  'U',  'V',  'W',  'X',  'Y',
		 'Z',  '[', '\\',  ']',  '^',  '_',  '`',  'A',  'B',  'C',
		 'D',  'E',  'F',  'G',  'H',  'I',  'J',  'K',  'L',  'M',
		 'N',  'O',  'P',  'Q',  'R',  'S',  'T',  'U',  'V',  'W',
		 'X',  'Y',  'Z',  '{',  '|',  '}',  '~', 0x7f, 0x80, 0x81,
		0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b,
		0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95,
		0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -202,6 +202,33 @@
 		req->state = Request::WAITING_FOR_APP_OUTPUT;
 		req->appSource.startReading();
 	}
+}
+
+static bool
+isAlphaNum(char ch) {
+	return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z');
+}
+
+/**
+ * For CGI, alphanum headers with optional dashes are mapped to UPP3R_CAS3. This
+ * function can be used to reject non-alphanum/dash headers that would end up with
+ * the same mapping (e.g. upp3r_cas3 and upp3r-cas3 would end up the same, and
+ * potentially collide each other in the receiving application). This is
+ * used to fix CVE-2015-7519.
+ */
+static bool
+containsNonAlphaNumDash(const LString &s) {
+	const LString::Part *part = s.start;
+	while (part != NULL) {
+		for (unsigned int i = 0; i < part->size; i++) {
+			const char start = part->data[i];
+			if (start != '-' && !isAlphaNum(start)) {
+				return true;
+			}
+		}
+		part = part->next;
+	}
+	return false;
 }
 
 static void
@@ -529,12 +556,18 @@
 
 	ServerKit::HeaderTable::Iterator it(req->headers);
 	while (*it != NULL) {
-		if ((it->header->hash == HTTP_CONTENT_LENGTH.hash()
-			|| it->header->hash == HTTP_CONTENT_TYPE.hash()
-			|| it->header->hash == HTTP_CONNECTION.hash())
-		 && (psg_lstr_cmp(&it->header->key, P_STATIC_STRING("content-type"))
-			|| psg_lstr_cmp(&it->header->key, P_STATIC_STRING("content-length"))
-			|| psg_lstr_cmp(&it->header->key, P_STATIC_STRING("connection"))))
+		// This header-skipping is not accounted for in determineHeaderSizeForSessionProtocol(), but
+		// since we are only reducing the size it just wastes some mem bytes.
+		if ((
+				(it->header->hash == HTTP_CONTENT_LENGTH.hash()
+						|| it->header->hash == HTTP_CONTENT_TYPE.hash()
+						|| it->header->hash == HTTP_CONNECTION.hash()
+				) && (psg_lstr_cmp(&it->header->key, P_STATIC_STRING("content-type"))
+						|| psg_lstr_cmp(&it->header->key, P_STATIC_STRING("content-length"))
+						|| psg_lstr_cmp(&it->header->key, P_STATIC_STRING("connection"))
+				)
+			) || containsNonAlphaNumDash(it->header->key)
+		   )
 		{
 			it.next();
 			continue;
```
