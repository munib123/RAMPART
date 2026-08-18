# CrossVul Fix Pair: Missing Authorization in typescript
**Pair ID:** 4470_3
**Vulnerability Class:** Missing Authorization
**CWE:** CWE-862
**Language:** typescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4470_3`)

## Vulnerability Information & PoC

## Description
Missing Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```typescript
Lines 1-21 of the vulnerable file.

import { sendToLagoonLogs } from '@lagoon/commons/dist/logs';
import { deleteProject } from '@lagoon/commons/dist/api';

import { WebhookRequestData } from '../types';

export async function gitlabProjectDelete(webhook: WebhookRequestData) {
  const {
    webhooktype,
    event,
    uuid,
    body,
    body: { path: name }
  } = webhook;

  try {
    const meta = {
      project: name
    };

    await deleteProject(name);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,5 +1,6 @@
+import R from 'ramda';
 import { sendToLagoonLogs } from '@lagoon/commons/dist/logs';
-import { deleteProject } from '@lagoon/commons/dist/api';
+import { allProjectsInGroup, deleteProject, sanitizeGroupName } from '@lagoon/commons/dist/api';
 
 import { WebhookRequestData } from '../types';
 
@@ -9,15 +10,37 @@
     event,
     uuid,
     body,
-    body: { path: name }
+    body: { path: projectName, path_with_namespace }
   } = webhook;
 
   try {
     const meta = {
-      project: name
+      project: projectName
     };
 
-    await deleteProject(name);
+    const groupName = sanitizeGroupName(path_with_namespace.replace(`/${projectName}`, ''));
+    const projectsInGroup = await allProjectsInGroup({ name: groupName });
+    const projectExists = R.pipe(
+      R.prop('allProjectsInGroup'),
+      R.pluck('name'),
+      R.contains(projectName),
+    // @ts-ignore
+    )(projectsInGroup);
+
+    if (projectExists) {
+      await deleteProject(projectName);
+
+      sendToLagoonLogs(
+        'info',
+        '',
+        uuid,
+        `${webhooktype}:${event}:handled`,
+        meta,
+        `deleted project ${projectName}`
+      );
+
+      return;
+    }
 
     sendToLagoonLogs(
       'info',
@@ -25,7 +48,7 @@
       uuid,
       `${webhooktype}:${event}:handled`,
       meta,
-      `deleted project ${name}`
+      `project "${projectName}" not a member of group "${groupName}"`
     );
 
     return;
```
