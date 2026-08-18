# CrossVul Fix Pair: Incorrect Permission Assignment for Critical Resource in javascript
**Pair ID:** 4455_1
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-732
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4455_1`)

## Vulnerability Information & PoC

## Description
Incorrect Permission Assignment for Critical Resource - When a resource is given a permission setting that provides access to a wider range of actors than required, it could lead to the exposure of sensitive information, or the modification of that reso...

## Vulnerable Code
```javascript
Lines 1-31 of the vulnerable file.

import RedisPubSub from '/imports/startup/server/redis';
import { check } from 'meteor/check';
import Polls from '/imports/api/polls';
import Logger from '/imports/startup/server/logger';
import { extractCredentials } from '/imports/api/common/server/helpers';

export default function publishVote(pollId, pollAnswerId) {
  const REDIS_CONFIG = Meteor.settings.private.redis;
  const CHANNEL = REDIS_CONFIG.channels.toAkkaApps;
  const EVENT_NAME = 'RespondToPollReqMsg';

  const { meetingId, requesterUserId } = extractCredentials(this.userId);

  check(pollAnswerId, Number);
  check(pollId, String);

  const selector = {
    users: requesterUserId,
    meetingId,
    'answers.id': pollAnswerId,
  };

  const payload = {
    requesterId: requesterUserId,
    pollId,
    questionId: 0,
    answerId: pollAnswerId,
  };

  /*
   We keep an array of people who were in the meeting at the time the poll
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8,11 +8,20 @@
   const REDIS_CONFIG = Meteor.settings.private.redis;
   const CHANNEL = REDIS_CONFIG.channels.toAkkaApps;
   const EVENT_NAME = 'RespondToPollReqMsg';
-
   const { meetingId, requesterUserId } = extractCredentials(this.userId);
 
   check(pollAnswerId, Number);
   check(pollId, String);
+
+  const waitingFor = Polls.findOne({ id: pollId }, {
+    feilds: {
+      users: 1,
+    },
+  });
+
+  const userResponded = !waitingFor.users.includes(requesterUserId);
+
+  if (userResponded) return null;
 
   const selector = {
     users: requesterUserId,
@@ -43,11 +52,11 @@
       return Logger.error(`Removing responded user from Polls collection: ${err}`);
     }
 
-    return Logger.info(`Removed responded user=${requesterUserId} from poll (meetingId: ${meetingId}, `
+    Logger.info(`Removed responded user=${requesterUserId} from poll (meetingId: ${meetingId}, `
       + `pollId: ${pollId}!)`);
+
+    return RedisPubSub.publishUserMessage(CHANNEL, EVENT_NAME, meetingId, requesterUserId, payload);
   };
 
   Polls.update(selector, modifier, cb);
-
-  return RedisPubSub.publishUserMessage(CHANNEL, EVENT_NAME, meetingId, requesterUserId, payload);
 }
```
