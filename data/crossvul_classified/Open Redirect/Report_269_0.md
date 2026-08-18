# CrossVul Fix Pair: URL Redirection to Untrusted Site ('Open Redirect') in go
**Pair ID:** 269_0
**Vulnerability Class:** Open Redirect
**CWE:** CWE-601
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `269_0`)

## Vulnerability Information & PoC

## Description
URL Redirection to Untrusted Site ('Open Redirect') - An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL.

## Vulnerable Code
```go
Lines 3-43 of the vulnerable file.

// found in the LICENSE file.

package views

import (
	"fmt"
	"github.com/s-gv/orangeforum/models"
	"github.com/s-gv/orangeforum/models/db"
	"github.com/s-gv/orangeforum/templates"
	"github.com/s-gv/orangeforum/utils"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var LoginHandler = UA(func(w http.ResponseWriter, r *http.Request, sess Session) {
	redirectURL, err := url.QueryUnescape(r.FormValue("next"))
	if redirectURL == "" || err != nil {
		redirectURL = "/"
	}
	if sess.IsUserValid() {
		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
		return
	}

	if r.Method == "POST" {
		userName := r.PostFormValue("username")
		passwd := r.PostFormValue("passwd")
		if len(userName) > 200 || len(passwd) > 200 {
			fmt.Fprint(w, "username / password too long.")
			return
		}
		if err = sess.Authenticate(userName, passwd); err == nil {
			http.Redirect(w, r, redirectURL, http.StatusSeeOther)
			return
		} else {
			sess.SetFlashMsg(err.Error())
			http.Redirect(w, r, "/login?next="+redirectURL, http.StatusSeeOther)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -20,7 +20,7 @@
 
 var LoginHandler = UA(func(w http.ResponseWriter, r *http.Request, sess Session) {
 	redirectURL, err := url.QueryUnescape(r.FormValue("next"))
-	if redirectURL == "" || err != nil {
+	if err != nil || redirectURL == "" || redirectURL[0] != '/' {
 		redirectURL = "/"
 	}
 	if sess.IsUserValid() {
@@ -59,7 +59,7 @@
 
 var SignupHandler = UA(func(w http.ResponseWriter, r *http.Request, sess Session) {
 	redirectURL, err := url.QueryUnescape(r.FormValue("next"))
-	if redirectURL == "" || err != nil {
+	if err != nil || redirectURL == "" || redirectURL[0] != '/' {
 		redirectURL = "/"
 	}
 	if sess.IsUserValid() && !sess.IsUserSuperAdmin() {
```
