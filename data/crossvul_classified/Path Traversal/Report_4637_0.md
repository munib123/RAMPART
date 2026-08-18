# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in typescript
**Pair ID:** 4637_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** typescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4637_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```typescript
Lines 140-180 of the vulnerable file.

    });

    router.post('/workspace', async (req, res) => {
      return upload(req, res, (err?: any) => {
        if (err) {
          return res.status(400).send(err.message);
        }

        return res.json(req.files);
      });
    });

    router.get(/^\/workspace\/(.*)/, async (req, res) => {
      const file = req.params[0];

      if (!file) {
        return res.sendStatus(400);
      }

      const filePath = path.join(workspaceDir, file);

      const hasFile = await exists(filePath);

      if (!hasFile) {
        return res.sendStatus(404);
      }

      const stats = await lstat(filePath);

      if (stats.isDirectory()) {
        const zipStream = archiver('zip');
        zipStream.pipe(res);
        return zipStream.directory(filePath, false).finalize();
      }

      return res.sendFile(filePath, {dotfiles: 'allow'});
    });

    router.delete(/^\/workspace\/(.*)/, async (req, res) => {
      const file = req.params[0];

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -157,8 +157,11 @@
       }
 
       const filePath = path.join(workspaceDir, file);
-
       const hasFile = await exists(filePath);
+
+      if (!filePath.includes(workspaceDir)) {
+        return res.sendStatus(404);
+      }
 
       if (!hasFile) {
         return res.sendStatus(404);
@@ -184,6 +187,10 @@
 
       const filePath = path.join(workspaceDir, file);
       const hasFile = await exists(filePath);
+
+      if (!filePath.includes(workspaceDir)) {
+        return res.sendStatus(404);
+      }
 
       if (!hasFile) {
         return res.sendStatus(404);
```
