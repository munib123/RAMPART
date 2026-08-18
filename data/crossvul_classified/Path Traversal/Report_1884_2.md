# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in java
**Pair ID:** 1884_2
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1884_2`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```java
Lines 43-83 of the vulnerable file.

        this.loggingPath = loggingPath;
        this.stylesheets = stylesheets;
        fileProviders = asList(new FileSystemFileProvider(),
                new ZipArchiveFileProvider(),
                new TarGzArchiveFileProvider());
        freemarkerConfig = new Configuration(Configuration.DEFAULT_INCOMPATIBLE_IMPROVEMENTS);
        freemarkerConfig.setClassForTemplateLoading(this.getClass(), "/templates");
    }

    @RequestMapping
    public void redirect(HttpServletResponse response) throws IOException {
        response.sendRedirect("log/");
    }

    @RequestMapping("/")
    @ResponseBody
    public String list(Model model, // TODO model should no longer be injected
                       @RequestParam(required = false, defaultValue = "FILENAME") SortBy sortBy,
                       @RequestParam(required = false, defaultValue = "false") boolean desc,
                       @RequestParam(required = false) String base) throws IOException, TemplateException {
        securityCheck(base);

        Path currentFolder = loggingPath(base);

        List<FileEntry> files = getFileProvider(currentFolder).getFileEntries(currentFolder);
        List<FileEntry> sortedFiles = sortFiles(files, sortBy, desc);

        model.addAttribute("sortBy", sortBy);
        model.addAttribute("desc", desc);
        model.addAttribute("files", sortedFiles);
        model.addAttribute("currentFolder", currentFolder.toAbsolutePath().toString());
        model.addAttribute("base", base != null ? URLEncoder.encode(base, "UTF-8") : "");
        model.addAttribute("parent", getParent(currentFolder));
        model.addAttribute("stylesheets", stylesheets);

        return FreeMarkerTemplateUtils.processTemplateIntoString(freemarkerConfig.getTemplate("logview.ftl"), model);
    }

    private FileProvider getFileProvider(Path folder) {
        return fileProviders.stream()
                .filter(provider -> provider.canHandle(folder))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -60,9 +60,9 @@
                        @RequestParam(required = false, defaultValue = "FILENAME") SortBy sortBy,
                        @RequestParam(required = false, defaultValue = "false") boolean desc,
                        @RequestParam(required = false) String base) throws IOException, TemplateException {
-        securityCheck(base);
-
         Path currentFolder = loggingPath(base);
+        securityCheck(currentFolder, null);
+
 
         List<FileEntry> files = getFileProvider(currentFolder).getFileEntries(currentFolder);
         List<FileEntry> sortedFiles = sortFiles(files, sortBy, desc);
@@ -127,10 +127,10 @@
                      @RequestParam(required = false) String base,
                      @RequestParam(required = false) Integer tailLines,
                      HttpServletResponse response) throws IOException {
-        securityCheck(filename);
+
+        Path path = loggingPath(base);
+        securityCheck(path, filename);
         response.setContentType(MediaType.TEXT_PLAIN_VALUE);
-
-        Path path = loggingPath(base);
         FileProvider fileProvider = getFileProvider(path);
         if (tailLines != null) {
             fileProvider.tailContent(path, filename, response.getOutputStream(), tailLines);
@@ -171,8 +171,15 @@
         }
     }
 
-    private void securityCheck(String filename) {
-        Assert.doesNotContain(filename, "..");
+    private void securityCheck(Path base, String filename) {
+        try {
+            String canonicalLoggingPath = (filename != null ? new File(base.toFile().toString(), filename) : new File(base.toFile().toString())).getCanonicalPath();
+            String baseCanonicalPath = new File(loggingPath).getCanonicalPath();
+            String errorMessage = "File " + base.toString() + "/" + filename + " may not be located outside base path " + loggingPath;
+            Assert.isTrue(canonicalLoggingPath.startsWith(baseCanonicalPath), errorMessage);
+        } catch (IOException e) {
+            throw new IllegalStateException(e);
+        }
     }
 
     @Override
```
