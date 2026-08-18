# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 3061_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3061_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 58-98 of the vulnerable file.

    );
  }.property("available_features"),
  is_supported_unmanaged_resource: function() {
    return (this.get("available_features").indexOf("unmanaged_resource") != -1);
  }.property("available_features"),
  is_sbd_running: false,
  is_sbd_enabled: false,
  is_sbd_enabled_or_running: function() {
    return (this.get("is_sbd_enabled") || this.get("is_sbd_running"));
  }.property("is_sbd_enabled", "is_sbd_running"),
  sbd_config: null,
  sbd_config_table: function() {
    if (!this.get("sbd_config")) {
      return "no configuration obtained";
    }
    var out =
      '<table class="darkdatatable"><tr><th>OPTION</th><th>VALUE</th></tr>\n';
    var banned_options = ["SBD_OPTS", "SBD_WATCHDOG_DEV", "SBD_PACEMAKER"];
    $.each(this.get("sbd_config"), function(opt, val) {
      if (banned_options.indexOf(opt) == -1) {
        out += '<tr><td>' + opt + '</td><td>' + val + '</td></tr>\n';
      }
    });
    return out + '</table>';
  }.property("sbd_config"),

  getResourcesFromID: function(resources) {
    var retArray = [];
    var resource_map = Pcs.resourcesContainer.get('resource_map');
    $.each(resources, function(_, resource_id) {
      if (resource_id in resource_map && !resource_map[resource_id].get('stonith')) {
        retArray.pushObject(resource_map[resource_id]);
      }
    });
    return retArray;
  },
  updater: null,

  update: function() {
    Pcs.get('updater').update();
  },
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -75,7 +75,7 @@
     var banned_options = ["SBD_OPTS", "SBD_WATCHDOG_DEV", "SBD_PACEMAKER"];
     $.each(this.get("sbd_config"), function(opt, val) {
       if (banned_options.indexOf(opt) == -1) {
-        out += '<tr><td>' + opt + '</td><td>' + val + '</td></tr>\n';
+        out += '<tr><td>' + htmlEncode(opt) + '</td><td>' + htmlEncode(val) + '</td></tr>\n';
       }
     });
     return out + '</table>';
@@ -879,7 +879,7 @@
   }.property("status_val"),
   show_status: function() {
     return '<span style="' + this.get('status_style') + '">'
-      + this.get('status') + (this.get("is_unmanaged") ? " (unmanaged)" : "")
+      + htmlEncode(this.get('status')) + (this.get("is_unmanaged") ? " (unmanaged)" : "")
       + '</span>';
   }.property("status_style", "disabled"),
   status_class: function() {
```
