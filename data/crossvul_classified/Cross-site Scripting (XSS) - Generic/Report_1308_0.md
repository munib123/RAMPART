# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in go
**Pair ID:** 1308_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1308_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```go
Lines 1-41 of the vulnerable file.

// Copyright 2016 Documize Inc. <legal@documize.com>. All rights reserved.
//
// This software (Documize Community Edition) is licensed under
// GNU AGPL v3 http://www.gnu.org/licenses/agpl-3.0.en.html
//
// You can operate outside the AGPL restrictions by purchasing
// Documize Enterprise Edition and obtaining a commercial license
// by contacting <sales@documize.com>.
//
// https://documize.com

package markdown

import (
	"net/http"

	"github.com/documize/blackfriday"
	"github.com/documize/community/core/env"
	"github.com/documize/community/domain/section/provider"
	"github.com/documize/community/domain/store"
)

// Provider represents Markdown
type Provider struct {
	Runtime *env.Runtime
	Store   *store.Store
}

// Meta describes us
func (*Provider) Meta() provider.TypeMeta {
	section := provider.TypeMeta{}

	section.ID = "1470bb4a-36c6-4a98-a443-096f5658378b"
	section.Title = "Markdown"
	section.Description = "CommonMark based content"
	section.ContentType = "markdown"
	section.PageType = "section"
	section.Order = 9998

	return section
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -18,6 +18,7 @@
 	"github.com/documize/community/core/env"
 	"github.com/documize/community/domain/section/provider"
 	"github.com/documize/community/domain/store"
+	"github.com/microcosm-cc/bluemonday"
 )
 
 // Provider represents Markdown
@@ -47,9 +48,11 @@
 
 // Render converts markdown data into HTML suitable for browser rendering.
 func (*Provider) Render(ctx *provider.Context, config, data string) string {
-	result := blackfriday.Run([]byte(data))
+	unsafe := blackfriday.Run([]byte(data))
 
-	return string(result)
+	safe := bluemonday.UGCPolicy().SanitizeBytes(unsafe)
+
+	return string(safe)
 }
 
 // Refresh just sends back data as-is.
```
