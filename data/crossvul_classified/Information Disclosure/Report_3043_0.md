# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in java
**Pair ID:** 3043_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3043_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```java
Lines 105-145 of the vulnerable file.

                try {
                    xmlEventReader.nextEvent();
                    return true;
                } catch (XMLStreamException e) {
                    throw new RuntimeException(e);
                }
            }
        }
        return false;
    }

    /**
     * Given an {@code Attribute}, get its trimmed value
     *
     * @param attribute
     *
     * @return
     */
    public static String getAttributeValue(Attribute attribute) {
        String str = trim(attribute.getValue());
        str = StringUtil.getSystemPropertyAsString(str);
        return str;
    }

    /**
     * Get the Attribute value
     *
     * @param startElement
     * @param tag localpart of the qname of the attribute
     *
     * @return
     */
    public static String getAttributeValue(StartElement startElement, String tag) {
        String result = null;
        Attribute attr = startElement.getAttributeByName(new QName(tag));
        if (attr != null)
            result = getAttributeValue(attr);
        return result;
    }

    /**
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -122,7 +122,6 @@
      */
     public static String getAttributeValue(Attribute attribute) {
         String str = trim(attribute.getValue());
-        str = StringUtil.getSystemPropertyAsString(str);
         return str;
     }
 
@@ -224,7 +223,6 @@
         String str = null;
         try {
             str = xmlEventReader.getElementText().trim();
-            str = StringUtil.getSystemPropertyAsString(str);
         } catch (XMLStreamException e) {
             throw logger.parserException(e);
         }
```
