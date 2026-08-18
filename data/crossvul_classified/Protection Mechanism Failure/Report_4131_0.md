# CrossVul Fix Pair: Protection Mechanism Failure in cpp
**Pair ID:** 4131_0
**Vulnerability Class:** Protection Mechanism Failure
**CWE:** CWE-693
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4131_0`)

## Vulnerability Information & PoC

## Description
Protection Mechanism Failure - This weakness covers three distinct situations.

## Vulnerable Code
```cpp
Lines 726-771 of the vulnerable file.

  auto api_web_contents =
      CreateAndTake(isolate(), std::move(new_contents), Type::BROWSER_WINDOW);
  if (Emit("-add-new-contents", api_web_contents, disposition, user_gesture,
           initial_rect.x(), initial_rect.y(), initial_rect.width(),
           initial_rect.height(), tracker->url, tracker->frame_name,
           tracker->referrer, tracker->raw_features, tracker->body)) {
    // TODO(zcbenz): Can we make this sync?
    api_web_contents->DestroyWebContents(true /* async */);
  }
}

content::WebContents* WebContents::OpenURLFromTab(
    content::WebContents* source,
    const content::OpenURLParams& params) {
  if (params.disposition != WindowOpenDisposition::CURRENT_TAB) {
    Emit("-new-window", params.url, "", params.disposition, "", params.referrer,
         params.post_data);
    return nullptr;
  }

  // Give user a chance to cancel navigation.
  if (Emit("will-navigate", params.url))
    return nullptr;

  // Don't load the URL if the web contents was marked as destroyed from a
  // will-navigate event listener
  if (IsDestroyed())
    return nullptr;

  return CommonWebContentsDelegate::OpenURLFromTab(source, params);
}

void WebContents::BeforeUnloadFired(content::WebContents* tab,
                                    bool proceed,
                                    bool* proceed_to_fire_unload) {
  if (type_ == Type::BROWSER_WINDOW || type_ == Type::OFF_SCREEN)
    *proceed_to_fire_unload = proceed;
  else
    *proceed_to_fire_unload = true;
  // Note that Chromium does not emit this for navigations.
  Emit("before-unload-fired", proceed);
}

void WebContents::SetContentsBounds(content::WebContents* source,
                                    const gfx::Rect& rect) {
  for (ExtendedWebContentsObserver& observer : observers_)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -743,12 +743,6 @@
     return nullptr;
   }
 
-  // Give user a chance to cancel navigation.
-  if (Emit("will-navigate", params.url))
-    return nullptr;
-
-  // Don't load the URL if the web contents was marked as destroyed from a
-  // will-navigate event listener
   if (IsDestroyed())
     return nullptr;
 
```
