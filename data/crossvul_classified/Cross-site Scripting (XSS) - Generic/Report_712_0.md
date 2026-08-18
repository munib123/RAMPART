# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in csharp
**Pair ID:** 712_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `712_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```csharp
Lines 73-113 of the vulnerable file.

                //If there was an exception trying to render a Error with a View, 
                //It can't handle errors so just write it out here.
                response = DtoUtils.CreateErrorResponse(req.Dto, ex);
            }

            //Handle Exceptions returning string
            if (req.ResponseContentType == MimeTypes.PlainText)
            {
                req.ResponseContentType = MimeTypes.Html;
                res.ContentType = MimeTypes.Html;
            }

            if (req.ResponseContentType != MimeTypes.Html && req.ResponseContentType != MimeTypes.JsonReport) 
                return;

            var dto = response.GetDto();
            if (!(dto is string html))
            {
                // Serialize then escape any potential script tags to avoid XSS when displaying as HTML
                var json = JsonDataContractSerializer.Instance.SerializeToString(dto) ?? "null";
                json = json.Replace("<", "&lt;").Replace(">", "&gt;");

                var url = req.ResolveAbsoluteUrl()
                    .Replace("format=html", "")
                    .Replace("format=shtm", "")
                    .TrimEnd('?', '&');

                url += url.Contains("?") ? "&" : "?";

                var now = DateTime.UtcNow;
                var requestName = req.OperationName ?? dto.GetType().GetOperationName();

                html = HtmlTemplates.GetHtmlFormatTemplate()
                    .Replace("${Dto}", json)
                    .Replace("${Title}", string.Format(TitleFormat, requestName, now))
                    .Replace("${MvcIncludes}", MiniProfiler.Profiler.RenderIncludes().ToString())
                    .Replace("${Header}", string.Format(HtmlTitleFormat, requestName, now))
                    .Replace("${ServiceUrl}", url)
                    .Replace("${Humanize}", Humanize.ToString().ToLower());
            }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -90,12 +90,13 @@
             {
                 // Serialize then escape any potential script tags to avoid XSS when displaying as HTML
                 var json = JsonDataContractSerializer.Instance.SerializeToString(dto) ?? "null";
-                json = json.Replace("<", "&lt;").Replace(">", "&gt;");
+                json = json.HtmlEncode();
 
                 var url = req.ResolveAbsoluteUrl()
                     .Replace("format=html", "")
                     .Replace("format=shtm", "")
-                    .TrimEnd('?', '&');
+                    .TrimEnd('?', '&')
+                    .HtmlEncode();
 
                 url += url.Contains("?") ? "&" : "?";
 
```
