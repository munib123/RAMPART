# CrossVul Fix Pair: Improper Input Validation in xml
**Pair ID:** 418_4
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `418_4`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```xml
Lines 729-749 of the vulnerable file.

    <string name="foreground_service_channel_description">This notification category is used to display a permanent notification indicating that Conversations is running.</string>
    <string name="notification_group_status_information">Status Information</string>
    <string name="error_channel_name">Connectivity Problems</string>
    <string name="error_channel_description">This notification category is used to display a notification in case there is a problem connecting to an account.</string>
    <string name="notification_group_messages">Messages</string>
    <string name="messages_channel_name">Messages</string>
    <string name="silent_messages_channel_name">Silent messages</string>
    <string name="silent_messages_channel_description">This notification group is used to display notifications that should not trigger any sound. For example when being active on another device (Grace Period).</string>
    <string name="pref_more_notification_settings">Notification Settings</string>
    <string name="pref_more_notification_settings_summary">Importance, Sound, Vibrate</string>
    <string name="video_compression_channel_name">Video compression</string>
    <string name="view_media">View media</string>
    <string name="media_browser">Media browser</string>
    <string name="export_channel_name">History export</string>
    <string name="security_violation_not_attaching_file">File omitted due to security violation.</string>
    <string name="pref_video_compression">Video Quality</string>
    <string name="pref_video_compression_summary">Lower quality means smaller files</string>
    <string name="video_360p">Medium (360p)</string>
    <string name="video_720p">High (720p)</string>
    <string name="cancelled">cancelled</string>
</resources>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -746,4 +746,5 @@
     <string name="video_360p">Medium (360p)</string>
     <string name="video_720p">High (720p)</string>
     <string name="cancelled">cancelled</string>
+    <string name="already_drafting_message">You are already drafting a message.</string>
 </resources>
```
