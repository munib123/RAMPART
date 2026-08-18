# CrossVul Fix Pair: Improper Neutralization of Special Elements used in a Command ('Command Injection') in javascript
**Pair ID:** 4627_0
**Vulnerability Class:** Command Injection - Generic
**CWE:** CWE-77
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4627_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in a Command ('Command Injection') - Command injection vulnerabilities typically occur when: 1.

## Vulnerable Code
```javascript
Lines 48-107 of the vulnerable file.

      // always return an array
      done(null, [source]);
    });
  }
}

function walkDir(fullPath) {
  const files = fs.readdirSync(fullPath).map(f => {
    const filePath = path.join(fullPath, f);
    const stats = fs.statSync(filePath);
    if (stats.isDirectory()) {
      return walkDir(filePath);
    }
    return filePath;
  });
  return files.reduce((acc, cur) => acc.concat(cur), []);
}

const nativeZip = options =>
  new Promise((resolve, reject) => {
    const sources = Array.isArray(options.source)
      ? options.source.join(" ")
      : options.source;
    const command = `zip --quiet --recurse-paths ${
      options.destination
    } ${sources}`;
    const zipProcess = cp.exec(command, {
      stdio: "inherit",
      cwd: options.cwd
    });
    zipProcess.on("error", reject);
    zipProcess.on("close", exitCode => {
      if (exitCode === 0) {
        resolve();
      } else {
        // exit code 12 means "nothing to do" right?
        //console.log('rejecting', zipProcess)
        reject(
          new Error(
            `Unexpected exit code from native zip command: ${exitCode}\n executed command '${command}'\n executed inin directory '${options.cwd ||
              process.cwd()}'`
          )
        );
      }
    });
  });

// based on http://stackoverflow.com/questions/15641243/need-to-zip-an-entire-directory-using-node-js/18775083#18775083
const nodeZip = options =>
  new Promise((resolve, reject) => {
    const cwd = options.cwd || process.cwd();
    const output = fs.createWriteStream(path.resolve(cwd, options.destination));
    const archive = archiver("zip");

    output.on("close", resolve);
    archive.on("error", reject);

    archive.pipe(output);

    function addSource(source, next) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -65,30 +65,32 @@
 
 const nativeZip = options =>
   new Promise((resolve, reject) => {
-    const sources = Array.isArray(options.source)
-      ? options.source.join(" ")
-      : options.source;
-    const command = `zip --quiet --recurse-paths ${
-      options.destination
-    } ${sources}`;
-    const zipProcess = cp.exec(command, {
-      stdio: "inherit",
-      cwd: options.cwd
-    });
-    zipProcess.on("error", reject);
-    zipProcess.on("close", exitCode => {
-      if (exitCode === 0) {
-        resolve();
-      } else {
-        // exit code 12 means "nothing to do" right?
-        //console.log('rejecting', zipProcess)
-        reject(
-          new Error(
-            `Unexpected exit code from native zip command: ${exitCode}\n executed command '${command}'\n executed inin directory '${options.cwd ||
-              process.cwd()}'`
-          )
-        );
-      }
+    const cwd = options.cwd || process.cwd();
+    const command = "zip";
+    expandSources(cwd, options.source, (err, sources) => {
+      const args = ["--quiet", "--recurse-paths", options.destination].concat(
+        sources
+      );
+      const zipProcess = cp.spawn(command, args, {
+        stdio: "inherit",
+        cwd
+      });
+      zipProcess.on("error", reject);
+      zipProcess.on("close", exitCode => {
+        if (exitCode === 0) {
+          resolve();
+        } else {
+          // exit code 12 means "nothing to do" right?
+          //console.log('rejecting', zipProcess)
+          reject(
+            new Error(
+              `Unexpected exit code from native zip: ${exitCode}\n executed command '${command} ${args.join(
+                " "
+              )}'\n executed in directory '${cwd}'`
+            )
+          );
+        }
+      });
     });
   });
 
```
