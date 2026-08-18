# CrossVul Fix Pair: Origin Validation Error in rust
**Pair ID:** 2992_0
**Vulnerability Class:** Origin Validation Error
**CWE:** CWE-346
**Language:** rust
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2992_0`)

## Vulnerability Information & PoC

## Description
Origin Validation Error - The product does not properly verify that the source of data or communication is valid.

## Vulnerable Code
```rust
Lines 54-94 of the vulnerable file.

#[cfg(test)]
extern crate env_logger;


mod endpoint;
mod apps;
mod page;
mod router;
mod handlers;
mod api;
mod proxypac;
mod url;
mod web;
#[cfg(test)]
mod tests;

use std::path::PathBuf;
use std::sync::Arc;
use std::collections::HashMap;

use jsonrpc_http_server::{self as http, hyper};

use fetch::Fetch;
use parity_reactor::Remote;

pub use hash_fetch::urlhint::ContractClient;

/// Indicates sync status
pub trait SyncStatus: Send + Sync {
	/// Returns true if there is a major sync happening.
	fn is_major_importing(&self) -> bool;
}

impl<F> SyncStatus for F where F: Fn() -> bool + Send + Sync {
	fn is_major_importing(&self) -> bool { self() }
}

/// Validates Web Proxy tokens
pub trait WebProxyTokens: Send + Sync {
	/// Should return true if token is a valid web proxy access token.
	fn is_web_proxy_token_valid(&self, token: &str) -> bool;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -71,7 +71,7 @@
 use std::sync::Arc;
 use std::collections::HashMap;
 
-use jsonrpc_http_server::{self as http, hyper};
+use jsonrpc_http_server::{self as http, hyper, Origin};
 
 use fetch::Fetch;
 use parity_reactor::Remote;
@@ -90,12 +90,12 @@
 
 /// Validates Web Proxy tokens
 pub trait WebProxyTokens: Send + Sync {
-	/// Should return true if token is a valid web proxy access token.
-	fn is_web_proxy_token_valid(&self, token: &str) -> bool;
-}
-
-impl<F> WebProxyTokens for F where F: Fn(String) -> bool + Send + Sync {
-	fn is_web_proxy_token_valid(&self, token: &str) -> bool { self(token.to_owned()) }
+	/// Should return a domain allowed to be accessed by this token or `None` if the token is not valid
+	fn domain(&self, token: &str) -> Option<Origin>;
+}
+
+impl<F> WebProxyTokens for F where F: Fn(String) -> Option<Origin> + Send + Sync {
+	fn domain(&self, token: &str) -> Option<Origin> { self(token.to_owned()) }
 }
 
 /// Current supported endpoints.
```
