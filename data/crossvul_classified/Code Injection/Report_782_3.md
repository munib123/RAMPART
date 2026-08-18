# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in typescript
**Pair ID:** 782_3
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** typescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `782_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```typescript
Lines 127-159 of the vulnerable file.

    for (const sassFile of options.files) {
      await compileSassAndSave(path.join(sassPath, sassFile), cssPath).then(cssFile => {
        console.log('Created', cssFile);
      }).catch(error => {
        reject(error);
      });
    }

    resolve();
  }).catch(error => {
    throw new Error(error);
  });
}


export function setupCleanupOnExit(cssPath: string) {
  if (!hasSetupCleanupOnExit){
    process.on('SIGINT', () => {
      console.log('Exiting, running CSS cleanup');

      exec(`rm -r ${cssPath}`, function(error) {
        if (error) {
          console.error(error);
          process.exit(1);
        }

        console.log('Deleted CSS files');
      });
    });

    hasSetupCleanupOnExit = true;
  }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -144,16 +144,24 @@
     process.on('SIGINT', () => {
       console.log('Exiting, running CSS cleanup');
 
-      exec(`rm -r ${cssPath}`, function(error) {
-        if (error) {
-          console.error(error);
+      fs.lstat(cssPath, (error: Error, stats: fs.Stats): void => {
+        if (stats.isDirectory) {
+          exec(`rm -r ${cssPath}`, function(error) {
+            if (error) {
+              console.error(error);
+              process.exit(1);
+            }
+    
+            console.log('Deleted CSS files');
+          });
+        }
+        else {
+          console.error('Could not delete CSS files because the given path is not a directory:', cssPath);
           process.exit(1);
         }
-
-        console.log('Deleted CSS files');
       });
+  
+      hasSetupCleanupOnExit = true;        
     });
-
-    hasSetupCleanupOnExit = true;
   }
 }
```
