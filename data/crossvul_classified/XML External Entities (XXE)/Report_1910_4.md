# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in java
**Pair ID:** 1910_4
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1910_4`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```java
Lines 292-332 of the vulnerable file.

    }

    private void refreshHttpProperties() throws IOException {
        logger.trace("Refreshing Denon status");

        updateMain();
        updateMainZone();
        updateSecondaryZones();
        updateDisplayInfo();
    }

    @Nullable
    private <T> T getDocument(String uri, Class<T> response) throws IOException {
        try {
            String result = HttpUtil.executeUrl("GET", uri, REQUEST_TIMEOUT_MS);
            logger.trace("result of getDocument for uri '{}':\r\n{}", uri, result);

            if (StringUtils.isNotBlank(result)) {
                JAXBContext jc = JAXBContext.newInstance(response);
                XMLInputFactory xif = XMLInputFactory.newInstance();
                XMLStreamReader xsr = xif.createXMLStreamReader(IOUtils.toInputStream(result));
                xsr = new PropertyRenamerDelegate(xsr);

                @SuppressWarnings("unchecked")
                T obj = (T) jc.createUnmarshaller().unmarshal(xsr);

                return obj;
            }
        } catch (UnmarshalException e) {
            logger.debug("Failed to unmarshal xml document: {}", e.getMessage());
        } catch (JAXBException e) {
            logger.debug("Unexpected error occurred during unmarshalling of document: {}", e.getMessage());
        } catch (XMLStreamException e) {
            logger.debug("Communication error: {}", e.getMessage());
        }

        return null;
    }

    @Nullable
    private <T, S> T postDocument(String uri, Class<T> response, S request) throws IOException {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -309,6 +309,8 @@
             if (StringUtils.isNotBlank(result)) {
                 JAXBContext jc = JAXBContext.newInstance(response);
                 XMLInputFactory xif = XMLInputFactory.newInstance();
+                xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
+                xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
                 XMLStreamReader xsr = xif.createXMLStreamReader(IOUtils.toInputStream(result));
                 xsr = new PropertyRenamerDelegate(xsr);
 
```
