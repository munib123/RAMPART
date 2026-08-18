# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 3253_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3253_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 267-307 of the vulnerable file.

		r_pkcs7_free_digestalgorithmidentifier (&sd->digestAlgorithms);
		r_pkcs7_free_contentinfo (&sd->contentInfo);
		r_pkcs7_free_extendedcertificatesandcertificates (&sd->certificates);
		r_pkcs7_free_certificaterevocationlists (&sd->crls);
		r_pkcs7_free_signerinfos (&sd->signerinfos);
		// Used internally pkcs #7, so it should't free sd.
	}
}

RCMS *r_pkcs7_parse_cms (const ut8 *buffer, ut32 length) {
	RASN1Object *object;
	RCMS *container;
	if (!buffer || !length) {
		return NULL;
	}
	container = R_NEW0 (RCMS);
	if (!container) {
		return NULL;
	}
	object = r_asn1_create_object (buffer, length);
	if (!object || object->list.length != 2 || !object->list.objects[0] || object->list.objects[1]->list.length != 1) {
		r_asn1_free_object (object);
		free (container);
		return NULL;
	}
	container->contentType = r_asn1_stringify_oid (object->list.objects[0]->sector, object->list.objects[0]->length);
	r_pkcs7_parse_signeddata (&container->signedData, object->list.objects[1]->list.objects[0]);
	r_asn1_free_object (object);
	return container;
}

void r_pkcs7_free_cms (RCMS* container) {
	if (container) {
		r_asn1_free_string (container->contentType);
		r_pkcs7_free_signeddata (&container->signedData);
		free (container);
	}
}

RPKCS7Attribute* r_pkcs7_parse_attribute (RASN1Object *object) {
	RPKCS7Attribute* attribute;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -284,7 +284,9 @@
 		return NULL;
 	}
 	object = r_asn1_create_object (buffer, length);
-	if (!object || object->list.length != 2 || !object->list.objects[0] || object->list.objects[1]->list.length != 1) {
+	if (!object || object->list.length != 2 || !object->list.objects ||
+		!object->list.objects[0] || !object->list.objects[1] ||
+		object->list.objects[1]->list.length != 1) {
 		r_asn1_free_object (object);
 		free (container);
 		return NULL;
```
