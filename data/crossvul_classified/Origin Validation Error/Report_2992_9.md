# CrossVul Fix Pair: Origin Validation Error in rust
**Pair ID:** 2992_9
**Vulnerability Class:** Origin Validation Error
**CWE:** CWE-346
**Language:** rust
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2992_9`)

## Vulnerability Information & PoC

## Description
Origin Validation Error - The product does not properly verify that the source of data or communication is valid.

## Vulnerable Code
```rust
Lines 215-255 of the vulnerable file.

mod server {
	use super::Dependencies;
	use std::path::PathBuf;
	use std::sync::Arc;
	use rpc_apis;

	use parity_dapps;
	use parity_reactor;

	pub use parity_dapps::Middleware;
	pub use parity_dapps::SyncStatus;

	pub fn dapps_middleware(
		deps: Dependencies,
		dapps_path: PathBuf,
		extra_dapps: Vec<PathBuf>,
		dapps_domain: String,
	) -> Result<Middleware, String> {
		let signer = deps.signer;
		let parity_remote = parity_reactor::Remote::new(deps.remote.clone());
		let web_proxy_tokens = Arc::new(move |token| signer.is_valid_web_proxy_access_token(&token));

		Ok(parity_dapps::Middleware::dapps(
			parity_remote,
			deps.ui_address,
			dapps_path,
			extra_dapps,
			dapps_domain,
			deps.contract_client,
			deps.sync_status,
			web_proxy_tokens,
			deps.fetch,
		))
	}

	pub fn ui_middleware(
		deps: Dependencies,
		dapps_domain: String,
	) -> Result<Middleware, String> {
		let parity_remote = parity_reactor::Remote::new(deps.remote.clone());
		Ok(parity_dapps::Middleware::ui(
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -232,7 +232,7 @@
 	) -> Result<Middleware, String> {
 		let signer = deps.signer;
 		let parity_remote = parity_reactor::Remote::new(deps.remote.clone());
-		let web_proxy_tokens = Arc::new(move |token| signer.is_valid_web_proxy_access_token(&token));
+		let web_proxy_tokens = Arc::new(move |token| signer.web_proxy_access_token_domain(&token));
 
 		Ok(parity_dapps::Middleware::dapps(
 			parity_remote,
```
