# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in java
**Pair ID:** 416_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `416_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```java
Lines 41-81 of the vulnerable file.

        }
        while (storageInfo != null);

        return key;
    }

    @PostMapping("/upload")
    public Object upload(@RequestParam("file") MultipartFile file) throws IOException {
        String originalFilename = file.getOriginalFilename();
        String url = storageService.store(file.getInputStream(), file.getSize(), file.getContentType(), originalFilename);

        Map<String, Object> data = new HashMap<>();
        data.put("url", url);
        return ResponseUtil.ok(data);
    }

    @GetMapping("/fetch/{key:.+}")
    public ResponseEntity<Resource> fetch(@PathVariable String key) {
        LitemallStorage litemallStorage = litemallStorageService.findByKey(key);
        if (key == null) {
            ResponseEntity.notFound();
        }
        String type = litemallStorage.getType();
        MediaType mediaType = MediaType.parseMediaType(type);

        Resource file = storageService.loadAsResource(key);
        if (file == null) {
            ResponseEntity.notFound();
        }
        return ResponseEntity.ok().contentType(mediaType).body(file);
    }

    @GetMapping("/download/{key:.+}")
    public ResponseEntity<Resource> download(@PathVariable String key) {
        LitemallStorage litemallStorage = litemallStorageService.findByKey(key);
        if (key == null) {
            ResponseEntity.notFound();
        }
        String type = litemallStorage.getType();
        MediaType mediaType = MediaType.parseMediaType(type);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -58,14 +58,17 @@
     public ResponseEntity<Resource> fetch(@PathVariable String key) {
         LitemallStorage litemallStorage = litemallStorageService.findByKey(key);
         if (key == null) {
-            ResponseEntity.notFound();
+            return ResponseEntity.notFound().build();
+        }
+        if(key.contains("../")){
+            return ResponseEntity.badRequest().build();
         }
         String type = litemallStorage.getType();
         MediaType mediaType = MediaType.parseMediaType(type);
 
         Resource file = storageService.loadAsResource(key);
         if (file == null) {
-            ResponseEntity.notFound();
+            return ResponseEntity.notFound().build();
         }
         return ResponseEntity.ok().contentType(mediaType).body(file);
     }
@@ -74,14 +77,18 @@
     public ResponseEntity<Resource> download(@PathVariable String key) {
         LitemallStorage litemallStorage = litemallStorageService.findByKey(key);
         if (key == null) {
-            ResponseEntity.notFound();
+            return ResponseEntity.notFound().build();
         }
+        if(key.contains("../")){
+            return ResponseEntity.badRequest().build();
+        }
+
         String type = litemallStorage.getType();
         MediaType mediaType = MediaType.parseMediaType(type);
 
         Resource file = storageService.loadAsResource(key);
         if (file == null) {
-            ResponseEntity.notFound();
+            return ResponseEntity.notFound().build();
         }
         return ResponseEntity.ok().contentType(mediaType).header(HttpHeaders.CONTENT_DISPOSITION,
                 "attachment; filename=\"" + file.getFilename() + "\"").body(file);
```
