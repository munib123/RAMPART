# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in javascript
**Pair ID:** 1990_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1990_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```javascript
Lines 1-30 of the vulnerable file.

"use strict";

const fs = require("fs").promises;
const SambaClient = require("./");

const testFile = "test.txt";

const client = new SambaClient({
  address: process.argv[2],
  username: "Guest",
});

async function run() {
  await fs.writeFile(testFile, testFile);

  await client.mkdir("test-directory");
  console.log(`created test directory on samba share at ${client.address}`);

  const list = await client.listFiles("eflex", ".txt");
  console.log(`found these files: ${list}`);

  await client.mkdir("test-directory");
  console.log(`created test directory on samba share at ${client.address}`);

  await client.sendFile(testFile, testFile);
  console.log(`sent test file to samba share at ${client.address}`);

  await fs.unlink(testFile);

  await client.getFile(testFile, testFile);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -7,19 +7,15 @@
 
 const client = new SambaClient({
   address: process.argv[2],
-  username: "Guest",
 });
 
 async function run() {
   await fs.writeFile(testFile, testFile);
 
-  await client.mkdir("test-directory");
-  console.log(`created test directory on samba share at ${client.address}`);
-
   const list = await client.listFiles("eflex", ".txt");
   console.log(`found these files: ${list}`);
 
-  await client.mkdir("test-directory");
+  await client.mkdir("test directory");
   console.log(`created test directory on samba share at ${client.address}`);
 
   await client.sendFile(testFile, testFile);
@@ -36,10 +32,8 @@
   } else {
     console.log(`test file does not exist on samba share at ${client.address}`);
   }
+
+  await fs.unlink(testFile);
 }
 
-process.on("exit", function () {
-  fs.unlinkSync(testFile);
-});
-
 run();
```
