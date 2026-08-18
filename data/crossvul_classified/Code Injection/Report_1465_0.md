# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in java
**Pair ID:** 1465_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1465_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```java
Lines 59-99 of the vulnerable file.

        String newFilter = filter;

        properties.put("%u", userName);

        userDomain = userName.split("@");

        properties.put("%U", userDomain[0]);

        if (userDomain.length > 1) {
            properties.put("%d", userDomain[1]);

            final String[] dcArray = userDomain[1].split("\\.");

            for (int i = 0; i < dcArray.length; i++) {
                properties.put("%" + (i + 1), dcArray[dcArray.length
                    - 1 - i]);
            }
        }

        for (final String key : properties.keySet()) {
            final String value = LdapEncoder.nameEncode(properties.get(key));
            newFilter = newFilter.replaceAll(key, Matcher.quoteReplacement(value));
        }

        return newFilter;
    }

    /**
     * Close the given context and ignore any thrown exception. This is useful
     * for typical finally blocks in manual Ldap statements.
     * 
     * @param context the Ldap context to close
     */
    public static void closeContext(final DirContext context) {
        if (context != null) {
            try {
                context.close();
            } catch (NamingException ex) {
                logger.warn("Could not close context", ex);
            }
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -76,7 +76,7 @@
         }
 
         for (final String key : properties.keySet()) {
-            final String value = LdapEncoder.nameEncode(properties.get(key));
+            final String value = LdapEncoder.filterEncode(properties.get(key));
             newFilter = newFilter.replaceAll(key, Matcher.quoteReplacement(value));
         }
 
```
