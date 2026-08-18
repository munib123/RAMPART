# CrossVul Fix Pair: Incorrect Authorization in javascript
**Pair ID:** 4553_1
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4553_1`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```javascript
Lines 1-34 of the vulnerable file.

import PromiseRouter from '../PromiseRouter';
import Config from '../Config';
import express from 'express';
import path from 'path';
import fs from 'fs';
import qs from 'querystring';
import { Parse } from 'parse/node';

const public_html = path.resolve(__dirname, '../../public_html');
const views = path.resolve(__dirname, '../../views');

export class PublicAPIRouter extends PromiseRouter {
  verifyEmail(req) {
    const { token, username } = req.query;
    const appId = req.params.appId;
    const config = Config.get(appId);

    if (!config) {
      this.invalidRequest();
    }

    if (!config.publicServerURL) {
      return this.missingPublicServerURL();
    }

    if (!token || !username) {
      return this.invalidLink(req);
    }

    const userController = config.userController;
    return userController.verifyEmail(username, token).then(
      () => {
        const params = qs.stringify({ username });
        return Promise.resolve({
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -11,7 +11,10 @@
 
 export class PublicAPIRouter extends PromiseRouter {
   verifyEmail(req) {
-    const { token, username } = req.query;
+    const { username, token: rawToken } = req.query;
+    const token =
+      rawToken && typeof rawToken !== 'string' ? rawToken.toString() : rawToken;
+
     const appId = req.params.appId;
     const config = Config.get(appId);
 
@@ -122,7 +125,9 @@
       return this.missingPublicServerURL();
     }
 
-    const { username, token } = req.query;
+    const { username, token: rawToken } = req.query;
+    const token =
+      rawToken && typeof rawToken !== 'string' ? rawToken.toString() : rawToken;
 
     if (!username || !token) {
       return this.invalidLink(req);
@@ -158,7 +163,9 @@
       return this.missingPublicServerURL();
     }
 
-    const { username, token, new_password } = req.body;
+    const { username, new_password, token: rawToken } = req.body;
+    const token =
+      rawToken && typeof rawToken !== 'string' ? rawToken.toString() : rawToken;
 
     if ((!username || !token || !new_password) && req.xhr === false) {
       return this.invalidLink(req);
```
