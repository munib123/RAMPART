# CrossVul Fix Pair: Origin Validation Error in rust
**Pair ID:** 2992_3
**Vulnerability Class:** Origin Validation Error
**CWE:** CWE-346
**Language:** rust
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2992_3`)

## Vulnerability Information & PoC

## Description
Origin Validation Error - The product does not properly verify that the source of data or communication is valid.

## Vulnerable Code
```rust
Lines 116-157 of the vulnerable file.


impl<F: Fetch> WebHandler<F> {
	fn extract_target_url(&self, url: Option<Url>) -> Result<String, State<F>> {
		let token_and_url = self.path.app_params.get(0)
			.map(|encoded| encoded.replace('.', ""))
			.and_then(|encoded| base32::decode(base32::Alphabet::Crockford, &encoded.to_uppercase()))
			.and_then(|data| String::from_utf8(data).ok())
			.ok_or_else(|| State::Error(ContentHandler::error(
				StatusCode::BadRequest,
				"Invalid parameter",
				"Couldn't parse given parameter:",
				self.path.app_params.get(0).map(String::as_str),
				self.embeddable_on.clone()
			)))?;

		let mut token_it = token_and_url.split('+');
		let token = token_it.next();
		let target_url = token_it.next();

		// Check if token supplied in URL is correct.
		match token {
			Some(token) if self.web_proxy_tokens.is_web_proxy_token_valid(token) => {},
			_ => {
				return Err(State::Error(ContentHandler::error(
					StatusCode::BadRequest, "Invalid Access Token", "Invalid or old web proxy access token supplied.", Some("Try refreshing the page."), self.embeddable_on.clone()
				)));
			}
		}

		// Validate protocol
		let mut target_url = match target_url {
			Some(url) if url.starts_with("http://") || url.starts_with("https://") => url.to_owned(),
			_ => {
				return Err(State::Error(ContentHandler::error(
					StatusCode::BadRequest, "Invalid Protocol", "Invalid protocol used.", None, self.embeddable_on.clone()
				)));
			}
		};

		if !target_url.ends_with("/") {
			target_url = format!("{}/", target_url);
		}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -133,14 +133,14 @@
 		let target_url = token_it.next();
 
 		// Check if token supplied in URL is correct.
-		match token {
-			Some(token) if self.web_proxy_tokens.is_web_proxy_token_valid(token) => {},
+		let domain = match token.and_then(|token| self.web_proxy_tokens.domain(token)) {
+			Some(domain) => domain,
 			_ => {
 				return Err(State::Error(ContentHandler::error(
 					StatusCode::BadRequest, "Invalid Access Token", "Invalid or old web proxy access token supplied.", Some("Try refreshing the page."), self.embeddable_on.clone()
 				)));
 			}
-		}
+		};
 
 		// Validate protocol
 		let mut target_url = match target_url {
@@ -151,6 +151,12 @@
 				)));
 			}
 		};
+
+		if !target_url.starts_with(&*domain) {
+			return Err(State::Error(ContentHandler::error(
+				StatusCode::BadRequest, "Invalid Domain", "Dapp attempted to access invalid domain.", Some(&target_url), self.embeddable_on.clone(),
+			)));
+		}
 
 		if !target_url.ends_with("/") {
 			target_url = format!("{}/", target_url);
```
