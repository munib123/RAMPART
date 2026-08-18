# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in java
**Pair ID:** 298_0
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `298_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```java
Lines 218-258 of the vulnerable file.

			reader.next();

			if (level == 0 && reader.isStartElement() && reader.getLocalName().equals(tagName)) {
				return true; //found
			}
		}
		return false; //got to end of parent element and not found
	}

	/**
	 * Try to parse SOAP method name from request body stream.  Does not close the stream.
	 *
	 * @param stream SOAP request body stream @nonnull
	 * @param charEncoding character encoding of stream, or null for platform default @null
	 * @return SOAP method name, or null if unable to parse @null
	 */
	private static String parseSoapMethodName(InputStream stream, String charEncoding) {
		try {
			// newInstance() et pas newFactory() pour java 1.5 (issue 367)
			final XMLInputFactory factory = XMLInputFactory.newInstance();
			final XMLStreamReader xmlReader;
			if (charEncoding != null) {
				xmlReader = factory.createXMLStreamReader(stream, charEncoding);
			} else {
				xmlReader = factory.createXMLStreamReader(stream);
			}

			//best-effort parsing

			//start document, go to first tag
			xmlReader.nextTag();

			//expect first tag to be "Envelope"
			if (!"Envelope".equals(xmlReader.getLocalName())) {
				LOG.debug("Unexpected first tag of SOAP request: '" + xmlReader.getLocalName()
						+ "' (expected 'Envelope')");
				return null; //failed
			}

			//scan for body tag
			if (!scanForChildTag(xmlReader, "Body")) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -235,6 +235,8 @@
 		try {
 			// newInstance() et pas newFactory() pour java 1.5 (issue 367)
 			final XMLInputFactory factory = XMLInputFactory.newInstance();
+			factory.setProperty(XMLInputFactory.SUPPORT_DTD, false); // disable DTDs entirely for that factory
+			factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false); // disable external entities
 			final XMLStreamReader xmlReader;
 			if (charEncoding != null) {
 				xmlReader = factory.createXMLStreamReader(stream, charEncoding);
```
