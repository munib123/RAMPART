# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in csharp
**Pair ID:** 4397_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4397_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```csharp
Lines 3184-3207 of the vulnerable file.

        }

        [Fact]
        public void PreParsedDocumentWithContextTest()
        {
            // parse a document before calling SantizeDom
            var sanitizer = new HtmlSanitizer();
            var parser = new HtmlParser(new HtmlParserOptions(), BrowsingContext.New(new Configuration().WithCss(new CssParserOptions
            {
                IsIncludingUnknownDeclarations = true,
                IsIncludingUnknownRules = true,
                IsToleratingInvalidSelectors = true,
            })));
            var html = @"<html><head></head><body><div>hi</div></body></html>";

            var document = parser.ParseDocument(html);
            var returnedDocument = sanitizer.SanitizeDom(document, document.Body);

            Assert.Equal("<html><head></head><body><div>hi</div></body></html>", returnedDocument.ToHtml());
        }
    }
}

#pragma warning restore 1591
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3201,6 +3201,19 @@
 
             Assert.Equal("<html><head></head><body><div>hi</div></body></html>", returnedDocument.ToHtml());
         }
+
+        [Fact]
+        public void StyleByPassTest()
+        {
+            var sanitizer = new HtmlSanitizer();
+
+            sanitizer.AllowedTags.Add("style");
+
+            var html = "aaabc<style>x[x='\\3c /style>\\3c img src onerror=alert(1)>']{}</style>";
+            var sanitized = sanitizer.Sanitize(html, "http://www.example.com");
+
+            Assert.Equal("aaabc<style>x[x=\"\\3c/style>\\3cimg src onerror=alert(1)>\"] { }</style>", sanitized);
+        }
     }
 }
 
```
