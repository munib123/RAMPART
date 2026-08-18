# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in java
**Pair ID:** 1910_6
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1910_6`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```java
Lines 138-178 of the vulnerable file.

         */
        INVALID_PIN
    }

    /**
     * Use {@link #getHNAPStatus()} to determine the status of the HNAP connection
     * after construction.
     *
     * @param ipAddress
     * @param pin
     */
    public DLinkHNAPCommunication(final String ipAddress, final String pin) {
        this.pin = pin;

        httpClient = new HttpClient();

        try {
            uri = new URI("http://" + ipAddress + "/HNAP1");
            httpClient.start();

            parser = DocumentBuilderFactory.newInstance().newDocumentBuilder();

            final MessageFactory messageFactory = MessageFactory.newInstance();
            requestAction = messageFactory.createMessage();
            loginAction = messageFactory.createMessage();

            buildRequestAction();
            buildLoginAction();
        } catch (final SOAPException e) {
            logger.debug("DLinkHNAPCommunication - Internal error", e);
            status = HNAPStatus.INTERNAL_ERROR;
        } catch (final URISyntaxException e) {
            logger.debug("DLinkHNAPCommunication - Internal error", e);
            status = HNAPStatus.INTERNAL_ERROR;
        } catch (final ParserConfigurationException e) {
            logger.debug("DLinkHNAPCommunication - Internal error", e);
            status = HNAPStatus.INTERNAL_ERROR;
        } catch (final Exception e) {
            // Thrown by httpClient.start()
            logger.debug("DLinkHNAPCommunication - Internal error", e);
            status = HNAPStatus.INTERNAL_ERROR;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -155,7 +155,14 @@
             uri = new URI("http://" + ipAddress + "/HNAP1");
             httpClient.start();
 
-            parser = DocumentBuilderFactory.newInstance().newDocumentBuilder();
+            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
+            // see https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
+            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
+            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
+            dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
+            dbf.setXIncludeAware(false);
+            dbf.setExpandEntityReferences(false);
+            parser = dbf.newDocumentBuilder();
 
             final MessageFactory messageFactory = MessageFactory.newInstance();
             requestAction = messageFactory.createMessage();
```
