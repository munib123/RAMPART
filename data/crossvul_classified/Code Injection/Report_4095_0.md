# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in go
**Pair ID:** 4095_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4095_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```go
Lines 179-219 of the vulnerable file.

	h := getString(ctx.Fasthttp.Response.Header.Peek(field))
	originalH := h
	for _, value := range values {
		if len(h) == 0 {
			h = value
		} else if h != value && !strings.HasSuffix(h, " "+value) &&
			!strings.Contains(h, value+",") {
			h += ", " + value
		}
	}
	if originalH != h {
		ctx.Set(field, h)
	}
}

// Attachment sets the HTTP response Content-Disposition header field to attachment.
func (ctx *Ctx) Attachment(filename ...string) {
	if len(filename) > 0 {
		fname := filepath.Base(filename[0])
		ctx.Type(filepath.Ext(fname))
		ctx.Set(HeaderContentDisposition, `attachment; filename="`+fname+`"`)
		return
	}
	ctx.Set(HeaderContentDisposition, "attachment")
}

// BaseURL returns (protocol + host + base path).
func (ctx *Ctx) BaseURL() string {
	// TODO: Could be improved: 53.8 ns/op  32 B/op  1 allocs/op
	// Should work like https://codeigniter.com/user_guide/helpers/url_helper.html
	return ctx.Protocol() + "://" + ctx.Hostname()
}

// Body contains the raw body submitted in a POST request.
// Returned value is only valid within the handler. Do not store any references.
// Make copies or use the Immutable setting instead.
func (ctx *Ctx) Body() string {
	return getString(ctx.Fasthttp.Request.Body())
}

// BodyParser binds the request body to a struct.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -196,7 +196,7 @@
 	if len(filename) > 0 {
 		fname := filepath.Base(filename[0])
 		ctx.Type(filepath.Ext(fname))
-		ctx.Set(HeaderContentDisposition, `attachment; filename="`+fname+`"`)
+		ctx.Set(HeaderContentDisposition, `attachment; filename="`+url.QueryEscape(fname)+`"`)
 		return
 	}
 	ctx.Set(HeaderContentDisposition, "attachment")
```
