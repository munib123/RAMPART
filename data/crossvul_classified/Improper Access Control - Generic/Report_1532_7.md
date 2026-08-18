# CrossVul Fix Pair: Improper Access Control in javascript
**Pair ID:** 1532_7
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1532_7`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```javascript
Lines 77-117 of the vulnerable file.

// Removes subscriptions that are no longer in the official list, not user submitted and no longer subscribed.
// Also, converts user submitted subscriptions to recognized one if it is already added to the official list
// and vice-versa.
MyFilters.prototype._updateDefaultSubscriptions = function() {
  if (!this._subscriptions) {
    // Brand new user. Install some filters for them.
    this._subscriptions = this._load_default_subscriptions();
    return;
  }

  for (var id in this._subscriptions) {
    // Delete unsubscribed ex-official lists.
    if (!this._official_options[id] && !this._subscriptions[id].user_submitted
        && !this._subscriptions[id].subscribed) {
      delete this._subscriptions[id];
    }
    // Convert subscribed ex-official lists into user-submitted lists.
    // Convert subscribed ex-user-submitted lists into official lists.
    else {
      // TODO: Remove this logic after a few releases
      if (id === "easylist_plus_spanish") {
          delete this._subscriptions[id];
          continue;
      }
      // Cache subscription that needs to be checked.
      var sub_to_check = this._subscriptions[id];
      var is_user_submitted = true;
      var update_id = id;
      if(!this._official_options[id]) {
        // If id is not in official options, check if there's a matching url in the
        // official list. If there is, then the subscription is not user submitted.
        for(var official_id in this._official_options) {
          var official_url = this._official_options[official_id].url;
          if(sub_to_check.initialUrl === official_url
            || sub_to_check.url === official_url) {
            is_user_submitted = false;
            update_id = official_id;
            break;
          }
        }
      } else {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -94,7 +94,7 @@
     // Convert subscribed ex-user-submitted lists into official lists.
     else {
       // TODO: Remove this logic after a few releases
-      if (id === "easylist_plus_spanish") {
+      if (id === "easylist_plus_spanish" || id === "norwegian") {
           delete this._subscriptions[id];
           continue;
       }
@@ -592,7 +592,6 @@
       case 'ko': return 'easylist_plun_korean';
       case 'lv': return 'latvian';
       case 'nl': return 'dutch';
-      case 'no': return 'norwegian';
       case 'pl': return 'easylist_plus_polish';
       case 'ro': return 'easylist_plus_romanian';
       case 'ru': return 'russian';
@@ -693,10 +692,6 @@
     },
     "latvian": {  // Latvian filters
       url: "https://gitorious.org/adblock-latvian/adblock-latvian/blobs/raw/master/lists/latvian-list.txt",
-    },
-    "norwegian": {  // Additional Norwegian filters
-      url: "http://home.fredfiber.no/langsholt/adblock.txt",
-      requiresList: "easylist",
     },
     "swedish": {  // Swedish filters
       url: "http://fanboy.co.nz/fanboy-swedish.txt",
```
