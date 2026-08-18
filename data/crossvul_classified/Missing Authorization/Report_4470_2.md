# CrossVul Fix Pair: Missing Authorization in typescript
**Pair ID:** 4470_2
**Vulnerability Class:** Missing Authorization
**CWE:** CWE-862
**Language:** typescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4470_2`)

## Vulnerability Information & PoC

## Description
Missing Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```typescript
Lines 1-25 of the vulnerable file.

import uuid4 from 'uuid4';
import url from 'url';
import R from 'ramda';
import { IncomingMessage } from 'http';

import type { RawData, WebhookRequestData } from './types';

/**
 * This function will check request headers for
 * service specific data like github / gitlab / etc.
 * if the request method is POST.
 *
 * Will eventually generate 'custom' webhook data on
 * GET requests.
 *
 * Will throw an error on malformed request headers,
 * non-json body data or unsupported method.
 */
export function extractWebhookData(req: IncomingMessage, body: string): WebhookRequestData {
  const { method, headers } = req;

  let parameters: any = {};
  let webhooktype;
  let event;
  let uuid;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,6 +2,7 @@
 import url from 'url';
 import R from 'ramda';
 import { IncomingMessage } from 'http';
+import { secureGitlabSystemHooks } from '@lagoon/commons/dist/gitlabApi';
 
 import type { RawData, WebhookRequestData } from './types';
 
@@ -45,7 +46,7 @@
       giturl = R.path(['project', 'git_ssh_url'], bodyObj);
 
       // This is a system webhook
-      if (!giturl) {
+      if (R.contains(event, secureGitlabSystemHooks)) {
         // Ensure the system hook came from gitlab
         if (!('x-gitlab-token' in req.headers) || req.headers['x-gitlab-token'] !== process.env.GITLAB_SYSTEM_HOOK_TOKEN) {
           throw new Error('Gitlab system hook secret verification failed');
```
