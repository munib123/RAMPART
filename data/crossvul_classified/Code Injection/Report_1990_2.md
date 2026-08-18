# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in javascript
**Pair ID:** 1990_2
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1990_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```javascript
Lines 1-24 of the vulnerable file.

"use strict";

const exec = require("child_process").exec;
const util = require("util");
const p = require("path");

const singleSlash = /\//g;
/*
 * NT_STATUS_NO_SUCH_FILE - when trying to dir a file in a directory that *does* exist
 * NT_STATUS_OBJECT_NAME_NOT_FOUND - when trying to dir a file in a directory that *does not* exist
 */
const missingFileRegex = /(NT_STATUS_OBJECT_NAME_NOT_FOUND|NT_STATUS_NO_SUCH_FILE)/im;

function wrap(str) {
  return "'" + str + "'";
}

class SambaClient {
  constructor(options) {
    this.address = options.address;
    this.username = wrap(options.username || "guest");
    this.password = options.password ? wrap(options.password) : null;
    this.domain = options.domain;
    this.port = options.port;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,7 +1,6 @@
 "use strict";
 
-const exec = require("child_process").exec;
-const util = require("util");
+const execa = require("execa");
 const p = require("path");
 
 const singleSlash = /\//g;
@@ -11,15 +10,14 @@
  */
 const missingFileRegex = /(NT_STATUS_OBJECT_NAME_NOT_FOUND|NT_STATUS_NO_SUCH_FILE)/im;
 
-function wrap(str) {
-  return "'" + str + "'";
-}
+const getCleanedSmbClientArgs = (args) =>
+  args.map((arg) => `"${arg.replace(singleSlash, "\\")}"`).join(" ");
 
 class SambaClient {
   constructor(options) {
     this.address = options.address;
-    this.username = wrap(options.username || "guest");
-    this.password = options.password ? wrap(options.password) : null;
+    this.username = options.username || "guest";
+    this.password = options.password;
     this.domain = options.domain;
     this.port = options.port;
     // Possible values for protocol version are listed in the Samba man pages:
@@ -28,35 +26,30 @@
     this.maskCmd = Boolean(options.maskCmd);
   }
 
-  getFile(path, destination, workingDir) {
-    const fileName = path.replace(singleSlash, "\\");
-    const cmdArgs = util.format("%s %s", fileName, destination);
-    return this.execute("get", cmdArgs, workingDir);
+  async getFile(path, destination, workingDir) {
+    return await this.execute("get", [path, destination], workingDir);
   }
 
-  sendFile(path, destination) {
+  async sendFile(path, destination) {
     const workingDir = p.dirname(path);
-    const fileName = p.basename(path).replace(singleSlash, "\\");
-    const cmdArgs = util.format(
-      "%s %s",
-      fileName,
-      destination.replace(singleSlash, "\\")
+    return await this.execute(
+      "put",
+      [p.basename(path), destination],
+      workingDir
     );
-    return this.execute("put", cmdArgs, workingDir);
   }
 
-  deleteFile(fileName) {
-    return this.execute("del", fileName, "");
+  async deleteFile(fileName) {
+    return await this.execute("del", [fileName], "");
   }
 
   async listFiles(fileNamePrefix, fileNameSuffix) {
     try {
-      const cmdArgs = util.format("%s*%s", fileNamePrefix, fileNameSuffix);
+      const cmdArgs = `${fileNamePrefix}*${fileNameSuffix}`;
       const allOutput = await this.execute("dir", cmdArgs, "");
       const fileList = [];
-      const lines = allOutput.split("\n");
-      for (let i = 0; i < lines.length; i++) {
-        const line = lines[i].toString().trim();
+      for (let line of allOutput.split("\n")) {
+        line = line.toString().trim();
         if (line.startsWith(fileNamePrefix)) {
           const parsed = line.substring(
             0,
@@ -75,20 +68,12 @@
     }
   }
 
-  mkdir(remotePath, cwd) {
-    return this.execute(
-      "mkdir",
-      remotePath.replace(singleSlash, "\\"),
-      cwd !== null && cwd !== undefined ? cwd : __dirname
-    );
+  async mkdir(remotePath, cwd) {
+    return await this.execute("mkdir", [remotePath], cwd || __dirname);
   }
 
-  dir(remotePath, cwd) {
-    return this.execute(
-      "dir",
-      remotePath.replace(singleSlash, "\\"),
-      cwd !== null && cwd !== undefined ? cwd : __dirname
-    );
+  async dir(remotePath, cwd) {
+    return await this.execute("dir", [remotePath], cwd || __dirname);
   }
 
   async fileExists(remotePath, cwd) {
@@ -112,25 +97,35 @@
   async list(remotePath) {
     const remoteDirList = [];
     const remoteDirContents = await this.dir(remotePath);
-    for(const content of remoteDirContents.matchAll(/\s*(.+?)\s{6,}(.)\s+([0-9]+)\s{2}(.+)/g)){
+    for (const content of remoteDirContents.matchAll(
+      /\s*(.+?)\s{6,}(.)\s+([0-9]+)\s{2}(.+)/g
+    )) {
       remoteDirList.push({
         name: content[1],
         type: content[2],
         size: parseInt(content[3]),
-        modifyTime: new Date(content[4]+'Z'),
+        modifyTime: new Date(content[4] + "Z"),
       });
     }
     return remoteDirList;
   }
 
-  getSmbClientArgs(fullCmd) {
-    const args = ["-U", this.username];
+  getSmbClientArgs(smbCommand, smbCommandArgs) {
+    const args = [];
+
+    if (this.username) {
+      args.push("-U", this.username);
+    }
 
     if (!this.password) {
       args.push("-N");
     }
 
-    args.push("-c", fullCmd, this.address);
+    let cleanedSmbArgs = smbCommandArgs;
+    if (Array.isArray(smbCommandArgs)) {
+      cleanedSmbArgs = getCleanedSmbClientArgs(smbCommandArgs);
+    }
+    args.push("-c", `${smbCommand} ${cleanedSmbArgs}`, this.address);
 
     if (this.password) {
       args.push(this.password);
@@ -153,57 +148,48 @@
     return args;
   }
 
-  execute(cmd, cmdArgs, workingDir) {
-    const fullCmd = wrap(util.format("%s %s", cmd, cmdArgs));
-    const command = [
-      "smbclient",
-      this.getSmbClientArgs(fullCmd).join(" "),
-    ].join(" ");
+  async execute(smbCommand, smbCommandArgs, workingDir) {
+    const args = this.getSmbClientArgs(smbCommand, smbCommandArgs);
 
     const options = {
+      all: true,
       cwd: workingDir || "",
     };
-    const maskCmd = this.maskCmd;
 
-    return new Promise((resolve, reject) => {
-      exec(command, options, function (err, stdout, stderr) {
-        const allOutput = stdout + stderr;
-
-        if (err) {
-          // The error message by default contains the whole smbclient command that was run
-          // This contains the username, password in plain text which can be a security risk
-          // maskCmd option allows user to hide the command from the error message
-          err.message = maskCmd ? allOutput : err.message + allOutput;
-          return reject(err);
-        }
-
-        return resolve(allOutput);
-      });
-    });
+    try {
+      const { all } = await execa("smbclient", args, options);
+      return all;
+    } catch (error) {
+      if (this.maskCmd) {
+        error.message = error.all;
+        error.shortMessage = error.all;
+      }
+      throw error;
+    }
   }
 
-  getAllShares() {
-    const maskCmd = this.maskCmd;
-    return new Promise((resolve, reject) => {
-      exec("smbtree -U guest -N", {}, function (err, stdout, stderr) {
-        const allOutput = stdout + stderr;
+  async getAllShares() {
+    try {
+      const { stdout } = await execa("smbtree", ["-U", "guest", "-N"], {
+        all: true,
+      });
 
-        if (err !== null) {
-          err.message = maskCmd ? allOutput : err.message + allOutput;
-          return reject(err);
+      const shares = [];
+      for (const line in stdout.split(/\r?\n/)) {
+        const words = line.split(/\t/);
+        if (words.length > 2 && words[2].match(/^\s*$/) !== null) {
+          shares.append(words[2].trim());
         }
+      }
 
-        const shares = [];
-        for (const line in stdout.split(/\r?\n/)) {
-          const words = line.split(/\t/);
-          if (words.length > 2 && words[2].match(/^\s*$/) !== null) {
-            shares.append(words[2].trim());
-          }
-        }
-
-        return resolve(shares);
-      });
-    });
+      return shares;
+    } catch (error) {
+      if (this.maskCmd) {
+        error.message = error.all;
+        error.shortMessage = error.all;
+      }
+      throw error;
+    }
   }
 }
 
```
