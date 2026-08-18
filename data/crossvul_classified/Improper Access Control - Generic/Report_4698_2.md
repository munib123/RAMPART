# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 4698_2
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4698_2`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 1029-1069 of the vulnerable file.

};

void
js_init() {
    /* This function creates the class and its definition, only once */
    if (!uzbl.js.initialized) {
        /* it would be pretty cool to make this dynamic */
        uzbl.js.classdef = kJSClassDefinitionEmpty;
        uzbl.js.classdef.staticFunctions = js_static_functions;

        uzbl.js.classref = JSClassCreate(&uzbl.js.classdef);
    }
}


void
eval_js(WebKitWebView * web_view, gchar *script, GString *result) {
    WebKitWebFrame *frame;
    JSGlobalContextRef context;
    JSObjectRef globalobject;
    JSStringRef var_name;

    JSStringRef js_script;
    JSValueRef js_result;
    JSStringRef js_result_string;
    size_t js_result_size;

    js_init();

    frame = webkit_web_view_get_main_frame(WEBKIT_WEB_VIEW(web_view));
    context = webkit_web_frame_get_global_context(frame);
    globalobject = JSContextGetGlobalObject(context);

    /* uzbl javascript namespace */
    var_name = JSStringCreateWithUTF8CString("Uzbl");
    JSObjectSetProperty(context, globalobject, var_name,
                        JSObjectMake(context, uzbl.js.classref, NULL),
                        kJSClassAttributeNone, NULL);

    /* evaluate the script and get return value*/
    js_script = JSStringCreateWithUTF8CString(script);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1046,7 +1046,6 @@
     WebKitWebFrame *frame;
     JSGlobalContextRef context;
     JSObjectRef globalobject;
-    JSStringRef var_name;
 
     JSStringRef js_script;
     JSValueRef js_result;
@@ -1058,12 +1057,6 @@
     frame = webkit_web_view_get_main_frame(WEBKIT_WEB_VIEW(web_view));
     context = webkit_web_frame_get_global_context(frame);
     globalobject = JSContextGetGlobalObject(context);
-
-    /* uzbl javascript namespace */
-    var_name = JSStringCreateWithUTF8CString("Uzbl");
-    JSObjectSetProperty(context, globalobject, var_name,
-                        JSObjectMake(context, uzbl.js.classref, NULL),
-                        kJSClassAttributeNone, NULL);
 
     /* evaluate the script and get return value*/
     js_script = JSStringCreateWithUTF8CString(script);
@@ -1082,9 +1075,6 @@
     }
 
     /* cleanup */
-    JSObjectDeleteProperty(context, globalobject, var_name, NULL);
-
-    JSStringRelease(var_name);
     JSStringRelease(js_script);
 }
 
```
