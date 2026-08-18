# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in rust
**Pair ID:** 1911_3
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** rust
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1911_3`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```rust
Lines 1-34 of the vulnerable file.

#![allow(dead_code)]

use crate::models::{Category, CategoryDB, Registration, Server};
use actix_files::NamedFile;
use actix_web::{get, middleware, web, App, HttpRequest, HttpResponse, HttpServer, Responder, Result as ActixResult};
use anyhow::Result;
use askama_actix::{Template, TemplateIntoResponse};
use dotenv::dotenv;
use listenfd::ListenFd;
use sqlx::PgPool;
use std::env;
use std::path::{Path, PathBuf};
use tracing::{info, instrument, Level};

mod models;

#[derive(Template, Debug)]
#[template(path = "index.html")]
struct IndexTemplate {
    categories: Vec<Category>,
    current_category: Option<Category>,
}

#[derive(Template, Debug)]
#[template(path = "details.html")]
struct DetailsTemplate {
    server: Server,
}

#[instrument]
#[get("/details/{server_url}")]
async fn details_endpoint(web::Path(server_url): web::Path<String>) -> impl Responder {
    // TODO get server from database
    let current_server = Server {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -11,8 +11,11 @@
 use std::env;
 use std::path::{Path, PathBuf};
 use tracing::{info, instrument, Level};
+use std::ffi::OsStr;
+use crate::errors::ServerError;
 
 mod models;
+mod errors;
 
 #[derive(Template, Debug)]
 #[template(path = "index.html")]
@@ -97,6 +100,10 @@
 #[instrument]
 async fn css(req: HttpRequest) -> ActixResult<NamedFile> {
     let path: PathBuf = req.match_info().query("filename").parse().unwrap();
+    if path.extension()
+        .and_then(OsStr::to_str) != "css" {
+        Err(ServerError::PathTraversal)
+    }
     let real_path = Path::new("assets/css/").join(path);
     Ok(NamedFile::open(real_path)?)
 }
@@ -104,6 +111,10 @@
 #[instrument]
 async fn js(req: HttpRequest) -> ActixResult<NamedFile> {
     let path: PathBuf = req.match_info().query("filename").parse().unwrap();
+    if path.extension()
+        .and_then(OsStr::to_str) != "js" {
+        Err(ServerError::PathTraversal)
+    }
     let real_path = Path::new("assets/js/").join(path);
     Ok(NamedFile::open(real_path)?)
 }
```
