# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in java
**Pair ID:** 1910_5
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1910_5`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```java
Lines 244-284 of the vulnerable file.

                }
            }

            // default zone count
            int zoneCount = 2;

            // try to determine the zone count by checking the Deviceinfo.xml file
            if (httpApiUsable) {
                int status = 0;
                response = null;
                try {
                    response = httpClient.newRequest("http://" + host + ":" + httpPort + "/goform/Deviceinfo.xml")
                            .timeout(3, TimeUnit.SECONDS).send();
                    status = response.getStatus();
                } catch (InterruptedException | TimeoutException | ExecutionException e) {
                    logger.debug("Failed in fetching the Deviceinfo.xml to determine zone count", e);
                }

                if (status == HttpURLConnection.HTTP_OK && response != null) {
                    DocumentBuilderFactory domFactory = DocumentBuilderFactory.newInstance();
                    DocumentBuilder builder;
                    try {
                        builder = domFactory.newDocumentBuilder();
                        Document dDoc = builder.parse(new InputSource(new StringReader(response.getContentAsString())));
                        XPath xPath = XPathFactory.newInstance().newXPath();
                        Node node = (Node) xPath.evaluate("/Device_Info/DeviceZones/text()", dDoc, XPathConstants.NODE);
                        if (node != null) {
                            String nodeValue = node.getNodeValue();
                            logger.trace("/Device_Info/DeviceZones/text() = {}", nodeValue);
                            zoneCount = Integer.parseInt(nodeValue);
                            logger.debug("Discovered number of zones: {}", zoneCount);
                        }
                    } catch (ParserConfigurationException | SAXException | IOException | XPathExpressionException
                            | NumberFormatException e) {
                        logger.debug("Something went wrong with looking up the zone count in Deviceinfo.xml: {}",
                                e.getMessage());
                    }
                }
            }
            config.setTelnet(telnetEnable);
            config.setZoneCount(zoneCount);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -261,8 +261,15 @@
 
                 if (status == HttpURLConnection.HTTP_OK && response != null) {
                     DocumentBuilderFactory domFactory = DocumentBuilderFactory.newInstance();
-                    DocumentBuilder builder;
                     try {
+                        // see
+                        // https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
+                        domFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
+                        domFactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
+                        domFactory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
+                        domFactory.setXIncludeAware(false);
+                        domFactory.setExpandEntityReferences(false);
+                        DocumentBuilder builder;
                         builder = domFactory.newDocumentBuilder();
                         Document dDoc = builder.parse(new InputSource(new StringReader(response.getContentAsString())));
                         XPath xPath = XPathFactory.newInstance().newXPath();
```
