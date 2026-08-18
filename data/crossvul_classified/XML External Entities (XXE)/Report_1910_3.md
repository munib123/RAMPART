# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in java
**Pair ID:** 1910_3
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1910_3`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```java
Lines 24-64 of the vulnerable file.

import org.xml.sax.helpers.XMLReaderFactory;

/**
 * The {@link XMLResponseProcessor} class handles the XML mapping
 *
 * @author Christian Niessner - Initial contribution
 * @author Thomas Traunbauer - Initial contribution
 */
public class XMLResponseProcessor {
    private BoseSoundTouchHandler handler;

    private Map<XMLHandlerState, Map<String, XMLHandlerState>> stateSwitchingMap;

    public XMLResponseProcessor(BoseSoundTouchHandler handler) {
        this.handler = handler;
        init();
    }

    public void handleMessage(String msg) throws SAXException, IOException {
        XMLReader reader = XMLReaderFactory.createXMLReader();
        reader.setContentHandler(new XMLResponseHandler(handler, stateSwitchingMap));
        reader.parse(new InputSource(new StringReader(msg)));
    }

    // initializes our XML parsing state machine
    private void init() {
        stateSwitchingMap = new HashMap<>();

        Map<String, XMLHandlerState> msgInitMap = new HashMap<>();
        stateSwitchingMap.put(XMLHandlerState.INIT, msgInitMap);
        msgInitMap.put("msg", XMLHandlerState.Msg);
        msgInitMap.put("SoundTouchSdkInfo", XMLHandlerState.Unprocessed);
        msgInitMap.put("userActivityUpdate", XMLHandlerState.Unprocessed); // ignored..

        Map<String, XMLHandlerState> msgBodyMap = new HashMap<>();
        stateSwitchingMap.put(XMLHandlerState.MsgBody, msgBodyMap);
        msgBodyMap.put("info", XMLHandlerState.Info);
        msgBodyMap.put("volume", XMLHandlerState.Volume);
        msgBodyMap.put("presets", XMLHandlerState.Presets);
        msgBodyMap.put("key", XMLHandlerState.Unprocessed); // only confirmation of our key presses...
        msgBodyMap.put("status", XMLHandlerState.Unprocessed); // only confirmation of commands sent to device...
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -41,6 +41,7 @@
 
     public void handleMessage(String msg) throws SAXException, IOException {
         XMLReader reader = XMLReaderFactory.createXMLReader();
+        reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
         reader.setContentHandler(new XMLResponseHandler(handler, stateSwitchingMap));
         reader.parse(new InputSource(new StringReader(msg)));
     }
```
