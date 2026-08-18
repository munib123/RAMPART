# CrossVul Fix Pair: Incorrect Permission Assignment for Critical Resource in java
**Pair ID:** 3081_0
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-732
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3081_0`)

## Vulnerability Information & PoC

## Description
Incorrect Permission Assignment for Critical Resource - When a resource is given a permission setting that provides access to a wider range of actors than required, it could lead to the exposure of sensitive information, or the modification of that reso...

## Vulnerable Code
```java
Lines 51-91 of the vulnerable file.

 * Utility service managing the various URI control REST APIs for each service instance. A single
 * utility service instance manages operations on multiple URI suffixes (/stats, /subscriptions,
 * etc) in order to reduce runtime overhead per service instance
 */
public class UtilityService implements Service {
    private transient Service parent;
    private ServiceStats stats;
    private ServiceSubscriptionState subscriptions;
    private UiContentService uiService;

    public UtilityService() {
    }

    public UtilityService setParent(Service parent) {
        this.parent = parent;
        return this;
    }

    @Override
    public void authorizeRequest(Operation op) {
        op.complete();
    }

    @Override
    public void handleRequest(Operation op) {
        String uriPrefix = this.parent.getSelfLink() + ServiceHost.SERVICE_URI_SUFFIX_UI;

        if (op.getUri().getPath().startsWith(uriPrefix)) {
            // startsWith catches all /factory/instance/ui/some-script.js
            handleUiRequest(op);
        } else if (op.getUri().getPath().endsWith(ServiceHost.SERVICE_URI_SUFFIX_STATS)) {
            handleStatsRequest(op);
        } else if (op.getUri().getPath().endsWith(ServiceHost.SERVICE_URI_SUFFIX_SUBSCRIPTIONS)) {
            handleSubscriptionsRequest(op);
        } else if (op.getUri().getPath().endsWith(ServiceHost.SERVICE_URI_SUFFIX_TEMPLATE)) {
            handleDocumentTemplateRequest(op);
        } else if (op.getUri().getPath().endsWith(ServiceHost.SERVICE_URI_SUFFIX_CONFIG)) {
            this.parent.handleConfigurationRequest(op);
        } else if (op.getUri().getPath().endsWith(ServiceHost.SERVICE_URI_SUFFIX_AVAILABLE)) {
            handleAvailableRequest(op);
        } else {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -68,7 +68,29 @@
 
     @Override
     public void authorizeRequest(Operation op) {
-        op.complete();
+
+        String suffix = UriUtils.buildUriPath(UriUtils.URI_PATH_CHAR, UriUtils.getLastPathSegment(op.getUri()));
+
+        // allow access to ui endpoint
+        if (ServiceHost.SERVICE_URI_SUFFIX_UI.equals(suffix)) {
+            op.complete();
+            return;
+        }
+
+        ServiceDocument doc = new ServiceDocument();
+        if (this.parent.getOptions().contains(ServiceOption.FACTORY_ITEM)) {
+            doc.documentSelfLink = UriUtils.buildUriPath(UriUtils.getParentPath(this.parent.getSelfLink()), suffix);
+        } else {
+            doc.documentSelfLink = UriUtils.buildUriPath(this.parent.getSelfLink(), suffix);
+        }
+
+        doc.documentKind = Utils.buildKind(this.parent.getStateType());
+        if (getHost().isAuthorized(this.parent, doc, op)) {
+            op.complete();
+            return;
+        }
+
+        op.fail(Operation.STATUS_CODE_FORBIDDEN);
     }
 
     @Override
```
