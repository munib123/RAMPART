# CrossVul Fix Pair: Origin Validation Error in rust
**Pair ID:** 2992_2
**Vulnerability Class:** Origin Validation Error
**CWE:** CWE-346
**Language:** rust
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2992_2`)

## Vulnerability Information & PoC

## Description
Origin Validation Error - The product does not properly verify that the source of data or communication is valid.

## Vulnerable Code
```rust
Lines 83-123 of the vulnerable file.

pub fn serve_with_registrar_and_sync() -> (Server, Arc<FakeRegistrar>) {
	init_server(|builder| {
		builder.sync_status(Arc::new(|| true))
	}, Default::default(), Remote::new_sync())
}

pub fn serve_with_registrar_and_fetch() -> (Server, FakeFetch, Arc<FakeRegistrar>) {
	serve_with_registrar_and_fetch_and_threads(false)
}

pub fn serve_with_registrar_and_fetch_and_threads(multi_threaded: bool) -> (Server, FakeFetch, Arc<FakeRegistrar>) {
	let fetch = FakeFetch::default();
	let f = fetch.clone();
	let (server, reg) = init_server(move |builder| {
		builder.fetch(f.clone())
	}, Default::default(), if multi_threaded { Remote::new_thread_per_future() } else { Remote::new_sync() });

	(server, fetch, reg)
}

pub fn serve_with_fetch(web_token: &'static str) -> (Server, FakeFetch) {
	let fetch = FakeFetch::default();
	let f = fetch.clone();
	let (server, _) = init_server(move |builder| {
		builder
			.fetch(f.clone())
			.web_proxy_tokens(Arc::new(move |token| &token == web_token))
	}, Default::default(), Remote::new_sync());

	(server, fetch)
}

pub fn serve() -> Server {
	init_server(|builder| builder, Default::default(), Remote::new_sync()).0
}

pub fn request(server: Server, request: &str) -> http_client::Response {
	http_client::request(server.addr(), request)
}

pub fn assert_security_headers(headers: &[String]) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -100,13 +100,15 @@
 	(server, fetch, reg)
 }
 
-pub fn serve_with_fetch(web_token: &'static str) -> (Server, FakeFetch) {
+pub fn serve_with_fetch(web_token: &'static str, domain: &'static str) -> (Server, FakeFetch) {
 	let fetch = FakeFetch::default();
 	let f = fetch.clone();
 	let (server, _) = init_server(move |builder| {
 		builder
 			.fetch(f.clone())
-			.web_proxy_tokens(Arc::new(move |token| &token == web_token))
+			.web_proxy_tokens(Arc::new(move |token| {
+				if &token == web_token { Some(domain.into()) } else { None }
+			}))
 	}, Default::default(), Remote::new_sync());
 
 	(server, fetch)
@@ -147,7 +149,7 @@
 			dapps_path: dapps_path.as_ref().to_owned(),
 			registrar: registrar,
 			sync_status: Arc::new(|| false),
-			web_proxy_tokens: Arc::new(|_| false),
+			web_proxy_tokens: Arc::new(|_| None),
 			signer_address: None,
 			allowed_hosts: DomainsValidation::Disabled,
 			remote: remote,
```
