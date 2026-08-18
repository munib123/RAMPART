# CrossVul Fix Pair: Missing Authorization in typescript
**Pair ID:** 4470_4
**Vulnerability Class:** Missing Authorization
**CWE:** CWE-862
**Language:** typescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4470_4`)

## Vulnerability Information & PoC

## Description
Missing Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```typescript
Lines 1-21 of the vulnerable file.

import { ChannelWrapper } from 'amqp-connection-manager';
import { ConsumeMessage } from 'amqplib';
import { processProjects } from './webhooks/projects';
import { processDataSync } from './webhooks/dataSync';
import { processBackup } from './webhooks/backup';
import { processProblems } from './webhooks/problems';
import { WebhookRequestData } from './types';

export async function processQueue (rabbitMsg: ConsumeMessage, channelWrapperWebhooks: ChannelWrapper): Promise<void> {
  const webhook: WebhookRequestData = JSON.parse(rabbitMsg.content.toString())

  const {
    webhooktype,
    giturl,
  } = webhook;

  // GitLab supports System Hooks which trigger on changes like creating new
  // organizations or users. Since these don't have associated projects, they
  // must be handled separately.
  if (webhooktype == 'gitlab' && !giturl) {
    processDataSync(rabbitMsg, channelWrapperWebhooks);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,5 +1,7 @@
+import R from 'ramda';
 import { ChannelWrapper } from 'amqp-connection-manager';
 import { ConsumeMessage } from 'amqplib';
+import { secureGitlabSystemHooks } from '@lagoon/commons/dist/gitlabApi';
 import { processProjects } from './webhooks/projects';
 import { processDataSync } from './webhooks/dataSync';
 import { processBackup } from './webhooks/backup';
@@ -11,13 +13,14 @@
 
   const {
     webhooktype,
+    event,
     giturl,
   } = webhook;
 
   // GitLab supports System Hooks which trigger on changes like creating new
   // organizations or users. Since these don't have associated projects, they
   // must be handled separately.
-  if (webhooktype == 'gitlab' && !giturl) {
+  if (webhooktype == 'gitlab' && R.contains(event, secureGitlabSystemHooks)) {
     processDataSync(rabbitMsg, channelWrapperWebhooks);
   } else if (webhooktype == 'resticbackup') {
     processBackup(rabbitMsg, channelWrapperWebhooks);
```
