# CrossVul Fix Pair: Insufficient Verification of Data Authenticity in json
**Pair ID:** 4289_3
**Vulnerability Class:** Insufficient Verification of Data Authenticity
**CWE:** CWE-345
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4289_3`)

## Vulnerability Information & PoC

## Description
Insufficient Verification of Data Authenticity - The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.

## Vulnerable Code
```json
Lines 1-39 of the vulnerable file.

{
  "name": "jitsi-meet-electron",
  "version": "2.2.0",
  "description": "Electron application for Jitsi Meet",
  "main": "./build/main.js",
  "productName": "Jitsi Meet",
  "scripts": {
    "start": "webpack --config ./webpack.main.js --mode development && concurrently \"npm:watch\" \"electron ./build/main.js\"",
    "clean": "rm -rf node_modules build dist",
    "lint": "eslint . && flow",
    "build": "webpack --config ./webpack.main.js --mode production && webpack --config ./webpack.renderer.js --mode production",
    "pack": "npm run build && electron-builder --dir",
    "dist": "npm run build && electron-builder",
    "postinstall": "patch-package && electron-builder install-app-deps",
    "validate": "npm ls",
    "watch": "webpack --config ./webpack.renderer.js --mode development --watch --watch-poll"
  },
  "engines" : {
    "node" : ">=12.0.0"
  },
  "build": {
    "appId": "org.jitsi.jitsi-meet",
    "productName": "Jitsi Meet",
    "generateUpdatesFilesForAllChannels": true,
    "files": [
      "**/*",
      "resources",
      "!app",
      "!main.js"
    ],
    "mac": {
      "artifactName": "jitsi-meet.${ext}",
      "category": "public.app-category.video",
      "darkModeSupport": true,
      "hardenedRuntime": true,
      "entitlements": "entitlements.mac.plist",
      "entitlementsInherit": "entitlements.mac.plist",
      "extendInfo": {
        "NSCameraUsageDescription": "Jitsi Meet requires access to your camera in order to make video-calls.",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -15,8 +15,8 @@
     "validate": "npm ls",
     "watch": "webpack --config ./webpack.renderer.js --mode development --watch --watch-poll"
   },
-  "engines" : {
-    "node" : ">=12.0.0"
+  "engines": {
+    "node": ">=12.0.0"
   },
   "build": {
     "appId": "org.jitsi.jitsi-meet",
```
