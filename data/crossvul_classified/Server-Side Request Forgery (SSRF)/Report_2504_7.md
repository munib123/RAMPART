# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in csharp
**Pair ID:** 2504_7
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2504_7`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```csharp
Lines 94-120 of the vulnerable file.

            throw new NotImplementedException();
        }
    }

    public sealed class Exports
    {
        public static RecurlyList<ExportDate> ListExportDates()
        {
            return new ExportDateList(ExportDate.UrlPrefix);
        }

        public static RecurlyList<ExportFile> ListExportFiles(DateTime date)
        {
            return new ExportFileList(string.Format(ExportFile.FilesUrlPrefix, date.ToString("yyyy-MM-dd")));
        }

        public static ExportFile DownloadExportFile(DateTime date, string fileName)
        {
            var exportFile = new ExportFile();
            var statusCode = Client.Instance.PerformRequest(Client.HttpRequestMethod.Get,
                string.Format(ExportFile.FileUrlPrefix, date.ToString("yyyy-MM-dd"), Uri.EscapeUriString(fileName)),
                exportFile.ReadXml);

            return statusCode != HttpStatusCode.NotFound ? exportFile : null;
        }
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -111,7 +111,7 @@
         {
             var exportFile = new ExportFile();
             var statusCode = Client.Instance.PerformRequest(Client.HttpRequestMethod.Get,
-                string.Format(ExportFile.FileUrlPrefix, date.ToString("yyyy-MM-dd"), Uri.EscapeUriString(fileName)),
+                string.Format(ExportFile.FileUrlPrefix, date.ToString("yyyy-MM-dd"), Uri.EscapeDataString(fileName)),
                 exportFile.ReadXml);
 
             return statusCode != HttpStatusCode.NotFound ? exportFile : null;
```
