# CrossVul Fix Pair: Improper Authentication in java
**Pair ID:** 2098_0
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2098_0`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```java
Lines 68-104 of the vulnerable file.

    /**
     * @see org.acegisecurity.ui.AbstractProcessingFilter#determineFailureUrl(javax.servlet.http.HttpServletRequest, org.acegisecurity.AuthenticationException)
     */
    @Override
    protected String determineFailureUrl(HttpServletRequest request, AuthenticationException failed) {
        Properties excMap = getExceptionMappings();
		String failedClassName = failed.getClass().getName();
		String whereFrom = request.getParameter("from");
		request.getSession().setAttribute("from", whereFrom);
		return excMap.getProperty(failedClassName, getAuthenticationFailureUrl());
    }

    @Override
    protected void onSuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, Authentication authResult) throws IOException {
        super.onSuccessfulAuthentication(request,response,authResult);
        // make sure we have a session to store this successful authentication, given that we no longer
        // let HttpSessionContextIntegrationFilter2 to create sessions.
        // HttpSessionContextIntegrationFilter stores the updated SecurityContext object into this session later
        // (either when a redirect is issued, via its HttpResponseWrapper, or when the execution returns to its
        // doFilter method.
        request.getSession();
    }

    /**
     * Leave the information about login failure.
     *
     * <p>
     * Otherwise it seems like Acegi doesn't really leave the detail of the failure anywhere.
     */
    @Override
    protected void onUnsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException {
        super.onUnsuccessfulAuthentication(request, response, failed);
        LOGGER.log(Level.INFO, "Login attempt failed", failed);
    }

    private static final Logger LOGGER = Logger.getLogger(AuthenticationProcessingFilter2.class.getName());
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -85,6 +85,7 @@
         // HttpSessionContextIntegrationFilter stores the updated SecurityContext object into this session later
         // (either when a redirect is issued, via its HttpResponseWrapper, or when the execution returns to its
         // doFilter method.
+        request.getSession().invalidate();
         request.getSession();
     }
 
```
