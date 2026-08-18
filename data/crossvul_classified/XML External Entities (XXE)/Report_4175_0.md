# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in java
**Pair ID:** 4175_0
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4175_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```java
Lines 77-117 of the vulnerable file.

        if (styleIdentifier > 0) {
            return Optional.of(Integer.parseInt(ref.substring(styleIdentifier + 2)) - 1);
        }
        return Optional.empty();
    }

    private Optional<Style> tryLoadSLD(
            final byte[] bytes, final Integer styleIndex,
            final ClientHttpRequestFactory clientHttpRequestFactory) {
        Assert.isTrue(styleIndex == null || styleIndex > -1,
                      "styleIndex must be > -1 but was: " + styleIndex);

        final Style[] styles;
        try {

            // check if the XML is valid
            // this is only done in a separate step to avoid that fatal errors show up in the logs
            // by setting a custom error handler.
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            DocumentBuilder db = dbf.newDocumentBuilder();
            db.setErrorHandler(new ErrorHandler());
            db.parse(new ByteArrayInputStream(bytes));

            // then read the styles
            final SLDParser sldParser = new SLDParser(CommonFactoryFinder.getStyleFactory());
            sldParser.setOnLineResourceLocator(new DefaultResourceLocator() {
                @Override
                public URL locateResource(final String uri) {
                    try {
                        final URL theUrl = super.locateResource(uri);
                        final URI theUri;
                        if (theUrl != null) {
                            theUri = theUrl.toURI();
                        } else {
                            theUri = URI.create(uri);
                        }
                        if (theUri.getScheme().startsWith("http")) {
                            final ClientHttpRequest request = clientHttpRequestFactory.createRequest(
                                    theUri, HttpMethod.GET);
                            return request.getURI().toURL();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -94,6 +94,7 @@
             // by setting a custom error handler.
             DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
             dbf.setNamespaceAware(true);
+            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
             DocumentBuilder db = dbf.newDocumentBuilder();
             db.setErrorHandler(new ErrorHandler());
             db.parse(new ByteArrayInputStream(bytes));
```
