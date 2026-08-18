# CrossVul Fix Pair: Improper Input Validation in cpp
**Pair ID:** 51_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `51_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```cpp
Lines 415-459 of the vulnerable file.

  return render_frame->GetPreviewsState() & content::NOSCRIPT_ON;
}

bool ContentSettingsObserver::AllowScript(bool enabled_per_settings) {
  if (!enabled_per_settings)
    return false;
  if (IsScriptDisabledForPreview(render_frame()))
    return false;
  if (is_interstitial_page_)
    return true;

  blink::WebLocalFrame* frame = render_frame()->GetWebFrame();
  const auto it = cached_script_permissions_.find(frame);
  if (it != cached_script_permissions_.end())
    return it->second;

  // Evaluate the content setting rules before
  // IsWhitelistedForContentSettings(); if there is only the default rule
  // allowing all scripts, it's quicker this way.
  bool allow = true;
  if (content_setting_rules_) {
    ContentSetting setting = GetContentSettingFromRules(
        content_setting_rules_->script_rules, frame,
        url::Origin(frame->GetDocument().GetSecurityOrigin()).GetURL());
    allow = setting != CONTENT_SETTING_BLOCK;
  }
  allow = allow || IsWhitelistedForContentSettings();

  cached_script_permissions_[frame] = allow;
  return allow;
}

bool ContentSettingsObserver::AllowScriptFromSource(
    bool enabled_per_settings,
    const blink::WebURL& script_url) {
  if (IsWhitelistedForContentSettings())
    return true;

  bool allow = enabled_per_settings;
  GURL secondary_url(script_url);
  if (content_settings_manager_->content_settings()) {
    allow =
        content_settings_manager_->GetSetting(
          ContentSettingsManager::GetOriginOrURL(render_frame()->GetWebFrame()),
          secondary_url,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -432,11 +432,13 @@
   // IsWhitelistedForContentSettings(); if there is only the default rule
   // allowing all scripts, it's quicker this way.
   bool allow = true;
-  if (content_setting_rules_) {
-    ContentSetting setting = GetContentSettingFromRules(
-        content_setting_rules_->script_rules, frame,
-        url::Origin(frame->GetDocument().GetSecurityOrigin()).GetURL());
-    allow = setting != CONTENT_SETTING_BLOCK;
+  if (content_settings_manager_->content_settings()) {
+    allow =
+        content_settings_manager_->GetSetting(
+          ContentSettingsManager::GetOriginOrURL(render_frame()->GetWebFrame()),
+          url::Origin(frame->GetDocument().GetSecurityOrigin()).GetURL(),
+          "javascript",
+          allow) != CONTENT_SETTING_BLOCK;
   }
   allow = allow || IsWhitelistedForContentSettings();
 
```
