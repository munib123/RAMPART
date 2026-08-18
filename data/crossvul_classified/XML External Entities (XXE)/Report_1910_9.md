# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in java
**Pair ID:** 1910_9
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1910_9`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```java
Lines 192-232 of the vulnerable file.

     */
    public String getSessionId() {
        final NodeList sessionIdTagList = xmlDoc.getElementsByTagName("sessionId");
        final String givenSessId = getCharacterDataFromElement((Element) sessionIdTagList.item(0));
        return givenSessId;
    }

    /**
     * converts the string we got from the radio to a parsable XML document
     *
     * @param xmlString
     *            the XML string read from the radio
     * @return the parsed XML document
     * @throws ParserConfigurationException
     * @throws SAXException
     * @throws IOException
     */
    private Document getXmlDocFromString(String xmlString)
            throws ParserConfigurationException, SAXException, IOException {
        final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        final DocumentBuilder builder = factory.newDocumentBuilder();
        final Document xmlDocument = builder.parse(new InputSource(new StringReader(xmlString)));
        return xmlDocument;
    }

    /**
     * convert the value of a given XML element to a string for further processing
     *
     * @param e
     *            XML Element
     * @return the elements value converted to string
     */
    private static String getCharacterDataFromElement(Element e) {
        final Node child = e.getFirstChild();
        if (child instanceof CharacterData) {
            final CharacterData cd = (CharacterData) child;
            return cd.getData();
        }
        return "";
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -209,6 +209,12 @@
     private Document getXmlDocFromString(String xmlString)
             throws ParserConfigurationException, SAXException, IOException {
         final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
+        // see https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
+        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
+        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
+        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
+        factory.setXIncludeAware(false);
+        factory.setExpandEntityReferences(false);
         final DocumentBuilder builder = factory.newDocumentBuilder();
         final Document xmlDocument = builder.parse(new InputSource(new StringReader(xmlString)));
         return xmlDocument;
```
