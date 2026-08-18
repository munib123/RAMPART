# CrossVul Fix Pair: Origin Validation Error in rust
**Pair ID:** 2992_1
**Vulnerability Class:** Origin Validation Error
**CWE:** CWE-346
**Language:** rust
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2992_1`)

## Vulnerability Information & PoC

## Description
Origin Validation Error - The product does not properly verify that the source of data or communication is valid.

## Vulnerable Code
```rust
Lines 295-335 of the vulnerable file.

	fetch.assert_requested("https://raw.githubusercontent.com/ethcore/dapp-assets/b88e983abaa1a6a6345b8d9448c15b117ddb540e/tokens/gavcoin-64x64.png");
	fetch.assert_no_more_requests();
	response1.assert_status("HTTP/1.1 200 OK");
	response2.assert_status("HTTP/1.1 200 OK");
}

#[test]
fn should_encode_and_decode_base32() {
	use base32;

	let encoded = base32::encode(base32::Alphabet::Crockford, "token+https://parity.io".as_bytes());
	assert_eq!("EHQPPSBE5DM78X3GECX2YBVGC5S6JX3S5SMPY", &encoded);

	let data = base32::decode(base32::Alphabet::Crockford, "EHQPPSBE5DM78X3GECX2YBVGC5S6JX3S5SMPY").unwrap();
	assert_eq!("token+https://parity.io", &String::from_utf8(data).unwrap());
}

#[test]
fn should_stream_web_content() {
	// given
	let (server, fetch) = serve_with_fetch("token");

	// when
	let response = request(server,
		"\
			GET / HTTP/1.1\r\n\
			Host: EHQPPSBE5DM78X3GECX2YBVGC5S6JX3S5SMPY.web.web3.site\r\n\
			Connection: close\r\n\
			\r\n\
		"
	);

	// then
	response.assert_status("HTTP/1.1 200 OK");
	assert_security_headers_for_embed(&response.headers);

	fetch.assert_requested("https://parity.io/");
	fetch.assert_no_more_requests();
}

#[test]
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -312,7 +312,7 @@
 #[test]
 fn should_stream_web_content() {
 	// given
-	let (server, fetch) = serve_with_fetch("token");
+	let (server, fetch) = serve_with_fetch("token", "https://parity.io");
 
 	// when
 	let response = request(server,
@@ -335,7 +335,7 @@
 #[test]
 fn should_support_base32_encoded_web_urls() {
 	// given
-	let (server, fetch) = serve_with_fetch("token");
+	let (server, fetch) = serve_with_fetch("token", "https://parity.io");
 
 	// when
 	let response = request(server,
@@ -358,7 +358,7 @@
 #[test]
 fn should_correctly_handle_long_label_when_splitted() {
 	// given
-	let (server, fetch) = serve_with_fetch("xolrg9fePeQyKLnL");
+	let (server, fetch) = serve_with_fetch("xolrg9fePeQyKLnL", "https://contribution.melonport.com");
 
 	// when
 	let response = request(server,
@@ -382,7 +382,7 @@
 #[test]
 fn should_support_base32_encoded_web_urls_as_path() {
 	// given
-	let (server, fetch) = serve_with_fetch("token");
+	let (server, fetch) = serve_with_fetch("token", "https://parity.io");
 
 	// when
 	let response = request(server,
@@ -403,9 +403,31 @@
 }
 
 #[test]
+fn should_return_error_on_non_whitelisted_domain() {
+	// given
+	let (server, fetch) = serve_with_fetch("token", "https://ethcore.io");
+
+	// when
+	let response = request(server,
+		"\
+			GET / HTTP/1.1\r\n\
+			Host: EHQPPSBE5DM78X3GECX2YBVGC5S6JX3S5SMPY.web.web3.site\r\n\
+			Connection: close\r\n\
+			\r\n\
+		"
+	);
+
+	// then
+	response.assert_status("HTTP/1.1 400 Bad Request");
+	assert_security_headers_for_embed(&response.headers);
+
+	fetch.assert_no_more_requests();
+}
+
+#[test]
 fn should_return_error_on_invalid_token() {
 	// given
-	let (server, fetch) = serve_with_fetch("test");
+	let (server, fetch) = serve_with_fetch("test", "https://parity.io");
 
 	// when
 	let response = request(server,
@@ -427,7 +449,7 @@
 #[test]
 fn should_return_error_on_invalid_protocol() {
 	// given
-	let (server, fetch) = serve_with_fetch("token");
+	let (server, fetch) = serve_with_fetch("token", "ftp://parity.io");
 
 	// when
 	let response = request(server,
@@ -449,7 +471,7 @@
 #[test]
 fn should_disallow_non_get_requests() {
 	// given
-	let (server, fetch) = serve_with_fetch("token");
+	let (server, fetch) = serve_with_fetch("token", "https://parity.io");
 
 	// when
 	let response = request(server,
@@ -474,7 +496,7 @@
 #[test]
 fn should_fix_absolute_requests_based_on_referer() {
 	// given
-	let (server, fetch) = serve_with_fetch("token");
+	let (server, fetch) = serve_with_fetch("token", "https://parity.io");
 
 	// when
 	let response = request(server,
@@ -497,7 +519,7 @@
 #[test]
 fn should_fix_absolute_requests_based_on_referer_in_url() {
 	// given
-	let (server, fetch) = serve_with_fetch("token");
+	let (server, fetch) = serve_with_fetch("token", "https://parity.io");
 
 	// when
 	let response = request(server,
```
