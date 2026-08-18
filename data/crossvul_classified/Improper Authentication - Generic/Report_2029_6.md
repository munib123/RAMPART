# CrossVul Fix Pair: Improper Authentication in java
**Pair ID:** 2029_6
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2029_6`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```java
Lines 88-130 of the vulnerable file.

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String path = httpRequest.getServletPath();
        LOG.debug("Handling request for path {}", path);

        if (configuration.getRealm() == null || configuration.getRealm().equals("") || !configuration.isEnabled()) {
            LOG.debug("No authentication needed for path {}", path);
            chain.doFilter(request, response);
            return;
        }

        HttpSession session = httpRequest.getSession(false);
        if (session != null) {
            Subject subject = (Subject) session.getAttribute("subject");
            if (subject != null) {
                LOG.debug("Session subject {}", subject);
                executeAs(request, response, chain, subject);
                return;
            }
        }

        boolean doAuthenticate = path.startsWith("/auth") ||
                path.startsWith("/jolokia") ||
                path.startsWith("/upload");

        if (doAuthenticate) {
            LOG.debug("Doing authentication and authorization for path {}", path);
            switch (Authenticator.authenticate(configuration.getRealm(), configuration.getRole(), configuration.getRolePrincipalClasses(),
                    configuration.getConfiguration(), httpRequest, new PrivilegedCallback() {
                public void execute(Subject subject) throws Exception {
                    executeAs(request, response, chain, subject);
                }
            })) {
                case AUTHORIZED:
                    // request was executed using the authenticated subject, nothing more to do
                    break;
                case NOT_AUTHORIZED:
                    Helpers.doForbidden((HttpServletResponse) response);
                    break;
                case NO_CREDENTIALS:
                    //doAuthPrompt((HttpServletResponse)response);
                    Helpers.doForbidden((HttpServletResponse) response);
                    break;
            }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -105,9 +105,7 @@
             }
         }
 
-        boolean doAuthenticate = path.startsWith("/auth") ||
-                path.startsWith("/jolokia") ||
-                path.startsWith("/upload");
+        boolean doAuthenticate = true;
 
         if (doAuthenticate) {
             LOG.debug("Doing authentication and authorization for path {}", path);
@@ -129,7 +127,7 @@
                     break;
             }
         } else {
-            LOG.debug("No authentication needed for path {}", path);
+            LOG.warn("No authentication needed for path {}", path);
             chain.doFilter(request, response);
         }
     }
```
