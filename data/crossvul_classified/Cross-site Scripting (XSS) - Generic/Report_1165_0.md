# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in java
**Pair ID:** 1165_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1165_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```java
Lines 517-557 of the vulnerable file.

        if (updateStarted) {
            writer.endUpdate();
        }
    }
    
    private void renderState(FacesContext context) throws IOException {
        // Get the view state and write it to the response..
        PartialViewContext pvc = context.getPartialViewContext();
        PartialResponseWriter writer = pvc.getPartialResponseWriter();
        String viewStateId = Util.getViewStateId(context);

        writer.startUpdate(viewStateId);
        String state = context.getApplication().getStateManager().getViewState(context);
        writer.write(state);
        writer.endUpdate();

        ClientWindow window = context.getExternalContext().getClientWindow();
        if (null != window) {
            String clientWindowId = Util.getClientWindowId(context);
            writer.startUpdate(clientWindowId);
            writer.write(window.getId());
            writer.endUpdate();
        }
    }

	private void renderEvalScripts(FacesContext context) throws IOException {
		PartialViewContext pvc = context.getPartialViewContext();
		PartialResponseWriter writer = pvc.getPartialResponseWriter();

		for (String evalScript : pvc.getEvalScripts()) {
			writer.startEval();
			writer.write(evalScript);
			writer.endEval();
		}
	}

    private PartialResponseWriter createPartialResponseWriter() {

        ExternalContext extContext = ctx.getExternalContext();
        String encoding = extContext.getRequestCharacterEncoding();
        extContext.setResponseCharacterEncoding(encoding);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -534,7 +534,7 @@
         if (null != window) {
             String clientWindowId = Util.getClientWindowId(context);
             writer.startUpdate(clientWindowId);
-            writer.write(window.getId());
+            writer.writeText(window.getId(), null);
             writer.endUpdate();
         }
     }
```
