# CrossVul Fix Pair: Improper Privilege Management in java
**Pair ID:** 3057_0
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3057_0`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```java
Lines 3603-3643 of the vulnerable file.

        req.getView(SecurityRealm.class, "signup.jelly").forward(req, rsp);
    }

    /**
     * Changes the icon size by changing the cookie
     */
    public void doIconSize( StaplerRequest req, StaplerResponse rsp ) throws IOException, ServletException {
        String qs = req.getQueryString();
        if(qs==null)
            throw new ServletException();
        Cookie cookie = new Cookie("iconSize", Functions.validateIconSize(qs));
        cookie.setMaxAge(/* ~4 mo. */9999999); // #762
        rsp.addCookie(cookie);
        String ref = req.getHeader("Referer");
        if(ref==null)   ref=".";
        rsp.sendRedirect2(ref);
    }

    @RequirePOST
    public void doFingerprintCleanup(StaplerResponse rsp) throws IOException {
        FingerprintCleanupThread.invoke();
        rsp.setStatus(HttpServletResponse.SC_OK);
        rsp.setContentType("text/plain");
        rsp.getWriter().println("Invoked");
    }

    @RequirePOST
    public void doWorkspaceCleanup(StaplerResponse rsp) throws IOException {
        WorkspaceCleanupThread.invoke();
        rsp.setStatus(HttpServletResponse.SC_OK);
        rsp.setContentType("text/plain");
        rsp.getWriter().println("Invoked");
    }

    /**
     * If the user chose the default JDK, make sure we got 'java' in PATH.
     */
    public FormValidation doDefaultJDKCheck(StaplerRequest request, @QueryParameter String value) {
        if(!value.equals(JDK.DEFAULT_NAME))
            // assume the user configured named ones properly in system config ---
            // or else system config should have reported form field validation errors.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3620,6 +3620,7 @@
 
     @RequirePOST
     public void doFingerprintCleanup(StaplerResponse rsp) throws IOException {
+        checkPermission(ADMINISTER);
         FingerprintCleanupThread.invoke();
         rsp.setStatus(HttpServletResponse.SC_OK);
         rsp.setContentType("text/plain");
@@ -3628,6 +3629,7 @@
 
     @RequirePOST
     public void doWorkspaceCleanup(StaplerResponse rsp) throws IOException {
+        checkPermission(ADMINISTER);
         WorkspaceCleanupThread.invoke();
         rsp.setStatus(HttpServletResponse.SC_OK);
         rsp.setContentType("text/plain");
```
