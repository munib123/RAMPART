# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 1977_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1977_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 1-38 of the vulnerable file.

/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

function loadSessionsTable(sessions) {
  $.each(sessions, function(index, session) {
    $("#interactive-sessions .sessions-table-body").append(
      "<tr>" +
        tdWrap(uiLink("session/" + session.id, session.id)) +
        tdWrap(appIdLink(session)) +
        tdWrap(session.name) +
        tdWrap(session.owner) +
        tdWrap(session.proxyUser) +
        tdWrap(session.kind) +
        tdWrap(session.state) +
        tdWrap(logLinks(session, "session")) +
        "</tr>"
    );
  });
}

function loadBatchesTable(sessions) {
  $.each(sessions, function(index, session) {
    $("#batches .sessions-table-body").append(
      "<tr>" +
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -15,13 +15,17 @@
  * limitations under the License.
  */
 
+function escapeHtml(unescapedText) {
+  return $("<div>").text(unescapedText).html()
+}
+
 function loadSessionsTable(sessions) {
   $.each(sessions, function(index, session) {
     $("#interactive-sessions .sessions-table-body").append(
       "<tr>" +
         tdWrap(uiLink("session/" + session.id, session.id)) +
         tdWrap(appIdLink(session)) +
-        tdWrap(session.name) +
+        tdWrap(escapeHtml(session.name)) +
         tdWrap(session.owner) +
         tdWrap(session.proxyUser) +
         tdWrap(session.kind) +
@@ -38,7 +42,7 @@
       "<tr>" +
         tdWrap(session.id) +
         tdWrap(appIdLink(session)) +
-        tdWrap(session.name) +
+        tdWrap(escapeHtml(session.name)) +
         tdWrap(session.owner) +
         tdWrap(session.proxyUser) +
         tdWrap(session.state) +
```
