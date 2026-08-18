# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in java
**Pair ID:** 2195_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2195_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```java
Lines 93-133 of the vulnerable file.

    /**
     * Disable XML Schema validation.  Note, setting this to true may not be reversable. Defaults to false. Setting it to false
     * after setting it to true may not have any affect.
     *
     * @param disabled whether to disable or not.
     */
    protected abstract void setDisableXmlSchemaValidation(boolean disabled);

    /**
     * Constructs the URL to send the validation request to.
     *
     * @param ticket the ticket to be validated.
     * @param serviceUrl the service identifier.
     * @return the fully constructed URL.
     */
    protected final String constructValidationUrl(final String ticket, final String serviceUrl) {
        final Map<String, String> urlParameters = new HashMap<String, String>();

        logger.debug("Placing URL parameters in map.");
        urlParameters.put("ticket", ticket);
        urlParameters.put("service", encodeUrl(serviceUrl));

        if (this.renew) {
            urlParameters.put("renew", "true");
        }

        logger.debug("Calling template URL attribute map.");
        populateUrlAttributeMap(urlParameters);

        logger.debug("Loading custom parameters from configuration.");
        if (this.customParameters != null) {
            urlParameters.putAll(this.customParameters);
        }

        final String suffix = getUrlSuffix();
        final StringBuilder buffer = new StringBuilder(urlParameters.size() * 10 + this.casServerUrlPrefix.length()
                + suffix.length() + 1);

        int i = 0;

        buffer.append(this.casServerUrlPrefix);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -110,7 +110,7 @@
 
         logger.debug("Placing URL parameters in map.");
         urlParameters.put("ticket", ticket);
-        urlParameters.put("service", encodeUrl(serviceUrl));
+        urlParameters.put("service", serviceUrl);
 
         if (this.renew) {
             urlParameters.put("renew", "true");
@@ -144,7 +144,8 @@
                 buffer.append(i++ == 0 ? "?" : "&");
                 buffer.append(key);
                 buffer.append("=");
-                buffer.append(value);
+                final String encodedValue = encodeUrl(value);
+                buffer.append(encodedValue);
             }
         }
 
```
