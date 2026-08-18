# CrossVul Fix Pair: Improper Input Validation in csharp
**Pair ID:** 869_3
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `869_3`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```csharp
Lines 15-55 of the vulnerable file.

{
    public interface IStorageService
    {
        string Location { get; }
        
        void CreateFolder(string path);
        void DeleteFolder(string path);
        void DeleteAuthor(string name);

        Task<AssetItem> UploadFormFile(IFormFile file, string root, string path = "");
        Task<AssetItem> UploadBase64Image(string baseImg, string root, string path = "");
        Task<AssetItem> UploadFromWeb(Uri requestUri, string root, string path = "");
        void DeleteFile(string path);

        IList<string> GetAssets(string path);
        IList<string> GetThemes();
        IList<WidgetItem> GetWidgets(string theme);

        string GetHtmlTemplate(string template);

        Task<IEnumerable<AssetItem>> Find(Func<AssetItem, bool> predicate, Pager pager, string path = "");

        Task Reset();
    }

    public class StorageService : IStorageService
    {
        string _blogSlug;
        string _separator = Path.DirectorySeparatorChar.ToString();
        string _uploadFolder = "data";
        IHttpContextAccessor _httpContext;

        private readonly ILogger _logger;

        public StorageService(IHttpContextAccessor httpContext, ILogger<StorageService> logger)
        {
            if(httpContext == null || httpContext.HttpContext == null)
            {
                _blogSlug = "";
            }
            else
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,7 +32,7 @@
 
         string GetHtmlTemplate(string template);
 
-        Task<IEnumerable<AssetItem>> Find(Func<AssetItem, bool> predicate, Pager pager, string path = "");
+        Task<IEnumerable<AssetItem>> Find(Func<AssetItem, bool> predicate, Pager pager, string path = "", bool sanitize = false);
 
         Task Reset();
     }
@@ -254,7 +254,7 @@
             }
         }
 
-        public async Task<IEnumerable<AssetItem>> Find(Func<AssetItem, bool> predicate, Pager pager, string path = "")
+        public async Task<IEnumerable<AssetItem>> Find(Func<AssetItem, bool> predicate, Pager pager, string path = "", bool sanitize = false)
         {
             var skip = pager.CurrentPage * pager.ItemsPerPage - pager.ItemsPerPage;
             var files = GetAssets(path);
@@ -266,6 +266,14 @@
             pager.Configure(items.Count);
 
             var page = items.Skip(skip).Take(pager.ItemsPerPage).ToList();
+
+            if (sanitize)
+            {
+                foreach (var p in page)
+                {
+                    p.Path = "";
+                }
+            }
 
             return await Task.FromResult(page);
         }
@@ -331,6 +339,8 @@
 
         void VerifyPath(string path)
         {
+            path = path.SanitizePath();
+
             if (!string.IsNullOrEmpty(path))
             {
                 var dir = Path.Combine(Location, path);
@@ -373,7 +383,7 @@
                 Random rnd = new Random();
                 fileName = fileName.Replace("mceclip0", rnd.Next(100000, 999999).ToString());
             }
-            return fileName;
+            return fileName.SanitizeFileName();
         }
 
         string GetUrl(string path, string root)
@@ -444,7 +454,7 @@
 
             title = title.Replace(" ", "-");
 
-            return title.Replace("/", "");
+            return title.Replace("/", "").SanitizeFileName();
         }
 
         List<AssetItem> MapFilesToAssets(IList<string> assets)
```
