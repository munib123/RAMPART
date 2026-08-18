# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in java
**Pair ID:** 4033_2
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4033_2`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```java
Lines 1509-1549 of the vulnerable file.

   */
  public void setHideUnprivilegedObjects(boolean hideUnprivileged) {
    PGProperty.HIDE_UNPRIVILEGED_OBJECTS.set(properties, hideUnprivileged);
  }

  public String getMaxResultBuffer() {
    return PGProperty.MAX_RESULT_BUFFER.get(properties);
  }

  public void setMaxResultBuffer(String maxResultBuffer) {
    PGProperty.MAX_RESULT_BUFFER.set(properties, maxResultBuffer);
  }

  //#if mvn.project.property.postgresql.jdbc.spec >= "JDBC4.1"
  @Override
  //#endif
  public java.util.logging.Logger getParentLogger() {
    return Logger.getLogger("org.postgresql");
  }

  /*
   * Alias methods below, these are to help with ease-of-use with other database tools / frameworks
   * which expect normal java bean getters / setters to exist for the property names.
   */

  public boolean isSsl() {
    return getSsl();
  }

  public String getSslfactoryarg() {
    return getSslFactoryArg();
  }

  public void setSslfactoryarg(final String arg) {
    setSslFactoryArg(arg);
  }

  public String getSslcert() {
    return getSslCert();
  }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1526,6 +1526,14 @@
     return Logger.getLogger("org.postgresql");
   }
 
+  public String getXmlFactoryFactory() {
+    return PGProperty.XML_FACTORY_FACTORY.get(properties);
+  }
+
+  public void setXmlFactoryFactory(String xmlFactoryFactory) {
+    PGProperty.XML_FACTORY_FACTORY.set(properties, xmlFactoryFactory);
+  }
+
   /*
    * Alias methods below, these are to help with ease-of-use with other database tools / frameworks
    * which expect normal java bean getters / setters to exist for the property names.
```
