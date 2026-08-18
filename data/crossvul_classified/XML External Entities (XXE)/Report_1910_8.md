# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in java
**Pair ID:** 1910_8
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1910_8`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```java
Lines 88-128 of the vulnerable file.

        }

        @SuppressWarnings("rawtypes")
        @Override
        public @Nullable Iterator getPrefixes(@Nullable String val) {
            return null;
        }

        @Override
        public @Nullable String getPrefix(@Nullable String uri) {
            return null;
        }
    };

    private DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
    private DocumentBuilder documentBuilder;

    public Client() {
        documentBuilderFactory.setNamespaceAware(true);
        try {
            documentBuilder = documentBuilderFactory.newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Query request and return the data
     *
     * @param request request to process
     * @param timeoutMillis timeout for the http call
     * @return data corresponding to the query
     * @throws FMIIOException on all I/O errors
     * @throws FMIUnexpectedResponseException on all unexpected content errors
     * @throw FMIExceptionReportException on explicit error responses from the server
     */
    public FMIResponse query(Request request, int timeoutMillis)
            throws FMIExceptionReportException, FMIUnexpectedResponseException, FMIIOException {
        try {
            String url = request.toUrl();
            String responseText = HttpUtil.executeUrl("GET", url, timeoutMillis);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -105,6 +105,12 @@
     public Client() {
         documentBuilderFactory.setNamespaceAware(true);
         try {
+            // see https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
+            documentBuilderFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
+            documentBuilderFactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
+            documentBuilderFactory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
+            documentBuilderFactory.setXIncludeAware(false);
+            documentBuilderFactory.setExpandEntityReferences(false);
             documentBuilder = documentBuilderFactory.newDocumentBuilder();
         } catch (ParserConfigurationException e) {
             throw new IllegalStateException(e);
```
