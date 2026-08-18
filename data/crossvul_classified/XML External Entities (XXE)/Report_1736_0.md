# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in java
**Pair ID:** 1736_0
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1736_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```java
Lines 36-76 of the vulnerable file.


/**
 * Simple implmentation which just parses the request body. If no xml is present
 * it will return an empty set.
 *
 * Note this generally shouldnt be used directly, but should be wrapped by
 * MSPropFindRequestFieldParser to support windows clients.
 *
 * @author brad
 */
public class DefaultPropFindRequestFieldParser implements PropFindRequestFieldParser {

    private static final Logger log = LoggerFactory.getLogger( DefaultPropFindRequestFieldParser.class );

    public DefaultPropFindRequestFieldParser() {
    }

	@Override
    public PropertiesRequest getRequestedFields( InputStream in ) {
		final Set<QName> set = new LinkedHashSet<QName>();
        try {            
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            StreamUtils.readTo( in, bout, false, true );
            byte[] arr = bout.toByteArray();
            if( arr.length > 1 ) {
                ByteArrayInputStream bin = new ByteArrayInputStream( arr );
                XMLReader reader = XMLReaderFactory.createXMLReader();
				reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
                PropFindSaxHandler handler = new PropFindSaxHandler();
                reader.setContentHandler( handler );
                try {
                    reader.parse( new InputSource( bin ) );
                    if( handler.isAllProp() ) {
                        return new PropertiesRequest();
                    } else {
                        set.addAll( handler.getAttributes().keySet() );
                    }
                } catch( IOException e ) {
                    log.warn( "exception parsing request body", e );
                    // ignore
                } catch( SAXException e ) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -53,7 +53,7 @@
 	@Override
     public PropertiesRequest getRequestedFields( InputStream in ) {
 		final Set<QName> set = new LinkedHashSet<QName>();
-        try {            
+        try {
             ByteArrayOutputStream bout = new ByteArrayOutputStream();
             StreamUtils.readTo( in, bout, false, true );
             byte[] arr = bout.toByteArray();
@@ -61,6 +61,9 @@
                 ByteArrayInputStream bin = new ByteArrayInputStream( arr );
                 XMLReader reader = XMLReaderFactory.createXMLReader();
 				reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
+				// https://www.owasp.org/index.php/XML_External_Entity_%28XXE%29_Processing
+				reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
+				reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
                 PropFindSaxHandler handler = new PropFindSaxHandler();
                 reader.setContentHandler( handler );
                 try {
@@ -77,7 +80,7 @@
                     log.warn( "exception parsing request body", e );
                     // ignore
                 }
-            }            
+            }
         } catch( Exception ex ) {
 			// There's a report of an exception being thrown here by IT Hit Webdav client
 			// Perhaps we can just log the error and return an empty set. Usually this
```
