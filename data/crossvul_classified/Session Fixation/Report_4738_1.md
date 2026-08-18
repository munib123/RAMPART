# CrossVul Fix Pair: Session Fixation in javascript
**Pair ID:** 4738_1
**Vulnerability Class:** Session Fixation
**CWE:** CWE-384
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4738_1`)

## Vulnerability Information & PoC

## Description
Session Fixation - Such a scenario is commonly observed when: A web application authenticates a user without first invalidating the existing session, thereby continuing to use the session already associated with the ...

## Vulnerable Code
```javascript
Lines 52-92 of the vulnerable file.

  updater: null,

  update: function() {
    Pcs.get('updater').update();
  },

  _update: function(first_run) {
    if (window.location.pathname.lastIndexOf('/manage', 0) !== 0) {
      return;
    }
    if (first_run) {
      show_loading_screen();
    }
    var self = Pcs;
    var cluster_name = self.cluster_name;
    if (cluster_name == null) {
      if (location.pathname.indexOf("/manage") != 0) {
        return;
      }
      Ember.debug("Empty Cluster Name");
      $.ajax({
        url: "/clusters_overview",
        dataType: "json",
        timeout: 20000,
        success: function(data) {
          Pcs.clusterController.update(data);
          if (Pcs.clusterController.get('cur_cluster')) {
            Pcs.clusterController.update_cur_cluster(Pcs.clusterController.get('cur_cluster').get('name'));
          }
          if (data["not_current_data"]) {
            self.update();
          }
          hide_loading_screen();
        },
        error: function(jqhxr,b,c) {
          if (jqhxr.responseText) {
            try {
              var obj = $.parseJSON(jqhxr.responseText);
              if (obj.notauthorized == "true") {
                location.reload();
              }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -69,7 +69,7 @@
         return;
       }
       Ember.debug("Empty Cluster Name");
-      $.ajax({
+      ajax_wrapper({
         url: "/clusters_overview",
         dataType: "json",
         timeout: 20000,
@@ -102,7 +102,7 @@
       });
       return;
     }
-    $.ajax({
+    ajax_wrapper({
       url: "cluster_status",
       dataType: "json",
       success: function(data) {
@@ -502,7 +502,7 @@
       value: value
     };
 
-    $.ajax({
+    ajax_wrapper({
       type: 'POST',
       url: get_cluster_remote_url() + 'add_meta_attr_remote',
       data: data,
@@ -523,7 +523,7 @@
     if (resource_id == null) {
       return;
     }
-    $.ajax({
+    ajax_wrapper({
       type: 'POST',
       url: get_cluster_remote_url() + 'resource_start',
       data: {resource: resource_id},
@@ -549,7 +549,7 @@
     if (resource_id == null) {
       return;
     }
-    $.ajax({
+    ajax_wrapper({
       type: 'POST',
       url: get_cluster_remote_url() + 'resource_stop',
       data: {resource: resource_id},
```
