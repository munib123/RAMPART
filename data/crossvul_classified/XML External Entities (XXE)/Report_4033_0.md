# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in java
**Pair ID:** 4033_0
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4033_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```java
Lines 644-684 of the vulnerable file.

    Integer.toString(Integer.MAX_VALUE),
    "Specifies the length to return for types of unknown length"),

  /**
   * Username to connect to the database as.
   */
  USER(
    "user",
    null,
    "Username to connect to the database as.",
    true),

  /**
   * Use SPNEGO in SSPI authentication requests.
   */
  USE_SPNEGO(
    "useSpnego",
    "false",
    "Use SPNEGO in SSPI authentication requests"),

  ;

  private final String name;
  private final String defaultValue;
  private final boolean required;
  private final String description;
  private final String[] choices;
  private final boolean deprecated;

  PGProperty(String name, String defaultValue, String description) {
    this(name, defaultValue, description, false);
  }

  PGProperty(String name, String defaultValue, String description, boolean required) {
    this(name, defaultValue, description, required, (String[]) null);
  }

  PGProperty(String name, String defaultValue, String description, boolean required, String[] choices) {
    this.name = name;
    this.defaultValue = defaultValue;
    this.required = required;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -660,6 +660,17 @@
     "useSpnego",
     "false",
     "Use SPNEGO in SSPI authentication requests"),
+
+  /**
+   * Factory class to instantiate factories for XML processing.
+   * The default factory disables external entity processing.
+   * Legacy behavior with external entity processing can be enabled by specifying a value of LEGACY_INSECURE.
+   * Or specify a custom class that implements {@code org.postgresql.xml.PGXmlFactoryFactory}.
+   */
+  XML_FACTORY_FACTORY(
+    "xmlFactoryFactory",
+    "",
+    "Factory class to instantiate factories for XML processing"),
 
   ;
 
```
