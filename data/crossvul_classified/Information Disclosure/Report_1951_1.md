# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in cpp
**Pair ID:** 1951_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1951_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```cpp
Lines 48-90 of the vulnerable file.

      return nullptr;
    }
    web_contents = content::WebContents::FromRenderFrameHost(rfh);
  }
  return web_contents;
}

}  // namespace

void ShouldBlockAdOnTaskRunner(std::shared_ptr<BraveRequestInfo> ctx,
                               base::Optional<std::string> canonical_name) {
  bool did_match_rule = false;
  bool did_match_exception = false;
  bool did_match_important = false;
  if (!ctx->initiator_url.is_valid()) {
    return;
  }
  std::string source_host = ctx->initiator_url.host();

  g_brave_browser_process->ad_block_service()->ShouldStartRequest(
        ctx->request_url, ctx->resource_type, source_host,
        &did_match_rule, &did_match_exception, &did_match_important,
        &ctx->mock_data_url);
  if (did_match_important) {
    ctx->blocked_by = kAdBlocked;
    return;
  }

  if (canonical_name.has_value() && ctx->request_url.host() != *canonical_name
      && *canonical_name != "") {
    GURL::Replacements replacements = GURL::Replacements();
    replacements.SetHost(
        canonical_name->c_str(),
        url::Component(0, static_cast<int>(canonical_name->length())));
    const GURL canonical_url = ctx->request_url.ReplaceComponents(replacements);

    g_brave_browser_process->ad_block_service()->ShouldStartRequest(
        ctx->request_url, ctx->resource_type, source_host,
        &did_match_rule, &did_match_exception, &did_match_important,
        &ctx->mock_data_url);
  }

  if (did_match_important || (did_match_rule && !did_match_exception)) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -65,16 +65,15 @@
   std::string source_host = ctx->initiator_url.host();
 
   g_brave_browser_process->ad_block_service()->ShouldStartRequest(
-        ctx->request_url, ctx->resource_type, source_host,
-        &did_match_rule, &did_match_exception, &did_match_important,
-        &ctx->mock_data_url);
+      ctx->request_url, ctx->resource_type, source_host, &did_match_rule,
+      &did_match_exception, &did_match_important, &ctx->mock_data_url);
   if (did_match_important) {
     ctx->blocked_by = kAdBlocked;
     return;
   }
 
-  if (canonical_name.has_value() && ctx->request_url.host() != *canonical_name
-      && *canonical_name != "") {
+  if (canonical_name.has_value() &&
+      ctx->request_url.host() != *canonical_name && *canonical_name != "") {
     GURL::Replacements replacements = GURL::Replacements();
     replacements.SetHost(
         canonical_name->c_str(),
@@ -82,9 +81,8 @@
     const GURL canonical_url = ctx->request_url.ReplaceComponents(replacements);
 
     g_brave_browser_process->ad_block_service()->ShouldStartRequest(
-        ctx->request_url, ctx->resource_type, source_host,
-        &did_match_rule, &did_match_exception, &did_match_important,
-        &ctx->mock_data_url);
+        ctx->request_url, ctx->resource_type, source_host, &did_match_rule,
+        &did_match_exception, &did_match_important, &ctx->mock_data_url);
   }
 
   if (did_match_important || (did_match_rule && !did_match_exception)) {
@@ -206,7 +204,16 @@
   scoped_refptr<base::SequencedTaskRunner> task_runner =
       g_brave_browser_process->ad_block_service()->GetTaskRunner();
 
-  new AdblockCnameResolveHostClient(std::move(next_callback), task_runner, ctx);
+  DCHECK(ctx->browser_context);
+  // DoH or standard DNS quries won't be routed through Tor, so we need to skip
+  // it.
+  if (ctx->browser_context->IsTor()) {
+    ShouldBlockAdWithOptionalCname(task_runner, std::move(next_callback), ctx,
+                                   base::nullopt);
+  } else {
+    new AdblockCnameResolveHostClient(std::move(next_callback), task_runner,
+                                      ctx);
+  }
 }
 
 int OnBeforeURLRequest_AdBlockTPPreWork(const ResponseCallback& next_callback,
```
