# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in java
**Pair ID:** 256_1
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `256_1`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```java
Lines 548-588 of the vulnerable file.

     * with that key as the prefix for locale specific resources.
     * </p>
     *
     * <p>
     * For example, say the request locale is en_US, and
     * <code>javax.faces.resourceLocalePrefix</code> is found with a value of
     * <code>en</code>, a resource path within a web application might look like
     * <code>/resources/en/corp/images/greetings.jpg</code>
     * </p>
     *
     * @param context the {@link FacesContext} for the current request
     * @return the localePrefix based on the current request, or <code>null</code>
     *  if no prefix can be determined
     */
    private String getLocalePrefix(FacesContext context) {

        String localePrefix = null;
        
        localePrefix = context.getExternalContext().getRequestParameterMap().get("loc");
        
        if(localePrefix != null){
            return localePrefix;
        }
        
        String appBundleName = context.getApplication().getMessageBundle();
        if (null != appBundleName) {
        	
            Locale locale = null;
            if (context.getViewRoot() != null) {
                locale = context.getViewRoot().getLocale();
            } else {
                locale = context.getApplication().getViewHandler().calculateLocale(context);
            }
            
                try {
                    ResourceBundle appBundle =
                          ResourceBundle.getBundle(appBundleName,
                                                   locale,
                                                   Util.getCurrentLoader(ResourceManager.class));
                    localePrefix =
                          appBundle
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -565,7 +565,7 @@
         
         localePrefix = context.getExternalContext().getRequestParameterMap().get("loc");
         
-        if(localePrefix != null){
+        if(localePrefix != null && !nameContainsForbiddenSequence(localePrefix)){
             return localePrefix;
         }
         
```
