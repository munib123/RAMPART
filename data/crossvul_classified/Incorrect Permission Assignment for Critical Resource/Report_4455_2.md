# CrossVul Fix Pair: Incorrect Permission Assignment for Critical Resource in javascript
**Pair ID:** 4455_2
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-732
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4455_2`)

## Vulnerability Information & PoC

## Description
Incorrect Permission Assignment for Critical Resource - When a resource is given a permission setting that provides access to a wider range of actors than required, it could lead to the exposure of sensitive information, or the modification of that reso...

## Vulnerable Code
```javascript
Lines 1-23 of the vulnerable file.

import { makeCall } from '/imports/ui/services/api';
import Polls from '/imports/api/polls';

const MAX_CHAR_LENGTH = 5;

const mapPolls = () => {
  const poll = Polls.findOne({});
  if (!poll) {
    return { pollExists: false };
  }

  const { answers } = poll;
  let stackOptions = false;

  answers.map((obj) => {
    if (stackOptions) return obj;
    if (obj.key.length > MAX_CHAR_LENGTH) {
      stackOptions = true;
    }
    return obj;
  });

  const amIRequester = poll.requester !== 'userId';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,7 +1,12 @@
 import { makeCall } from '/imports/ui/services/api';
 import Polls from '/imports/api/polls';
+import { debounce } from 'lodash';
 
 const MAX_CHAR_LENGTH = 5;
+
+const handleVote = (pollId, answerId) => {
+  makeCall('publishVote', pollId, answerId.id);
+};
 
 const mapPolls = () => {
   const poll = Polls.findOne({});
@@ -30,9 +35,7 @@
     },
     pollExists: true,
     amIRequester,
-    handleVote(pollId, answerId) {
-      makeCall('publishVote', pollId, answerId.id);
-    },
+    handleVote: debounce(handleVote, 500, { leading: true, trailing: false }),
   };
 };
 
```
