# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in java
**Pair ID:** 1736_1
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1736_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```java
Lines 52-83 of the vulnerable file.

            StreamUtils.readTo( in, bout, false, true );
            byte[] arr = bout.toByteArray();
            return parseContent( arr );
        } catch( SAXException ex ) {
            throw new RuntimeException( ex );
        } catch( ReadingException ex ) {
            throw new RuntimeException( ex );
        } catch( WritingException ex ) {
            throw new RuntimeException( ex );
        } catch( IOException ex ) {
            throw new RuntimeException( ex );
        }
    }

    private PropPatchParseResult parseContent( byte[] arr ) throws IOException, SAXException {
        if( arr.length > 0 ) {
            log.debug( "processing content" );
            ByteArrayInputStream bin = new ByteArrayInputStream( arr );
            XMLReader reader = XMLReaderFactory.createXMLReader();
			reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            PropPatchSaxHandler handler = new PropPatchSaxHandler();
            reader.setContentHandler( handler );
            reader.parse( new InputSource( bin ) );
            log.debug( "toset: " + handler.getAttributesToSet().size());
            return new PropPatchParseResult( handler.getAttributesToSet(), handler.getAttributesToRemove().keySet() );
        } else {
            log.debug( "empty content" );
            return new PropPatchParseResult( new HashMap<QName, String>(), new HashSet<QName>() );
        }

    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -69,6 +69,10 @@
             ByteArrayInputStream bin = new ByteArrayInputStream( arr );
             XMLReader reader = XMLReaderFactory.createXMLReader();
 			reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
+			// https://www.owasp.org/index.php/XML_External_Entity_%28XXE%29_Processing
+			reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
+			reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
+
             PropPatchSaxHandler handler = new PropPatchSaxHandler();
             reader.setContentHandler( handler );
             reader.parse( new InputSource( bin ) );
```
