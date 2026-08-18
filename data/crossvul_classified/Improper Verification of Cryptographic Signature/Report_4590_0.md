# CrossVul Fix Pair: Improper Verification of Cryptographic Signature in python
**Pair ID:** 4590_0
**Vulnerability Class:** Improper Verification of Cryptographic Signature
**CWE:** CWE-347
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4590_0`)

## Vulnerability Information & PoC

## Description
Improper Verification of Cryptographic Signature - The product does not verify, or incorrectly verifies, the cryptographic signature for data.

## Vulnerable Code
```python
Lines 1459-1499 of the vulnerable file.

                else:
                    certs.append(cert)
        else:
            certs = []

        if not certs and not self.only_use_keys_in_metadata:
            logger.debug('==== Certs from instance ====')
            certs = [
                make_temp(content=pem_format(cert),
                          suffix=".pem",
                          decode=False,
                          delete_tmpfiles=self.delete_tmpfiles)
                for cert in cert_from_instance(item)
            ]
        else:
            logger.debug('==== Certs from metadata ==== %s: %s ====', _issuer, certs)

        if not certs:
            raise MissingKey(_issuer)

        verified = False
        last_pem_file = None

        for pem_fd in certs:
            try:
                last_pem_file = pem_fd.name
                if self.verify_signature(
                        decoded_xml,
                        pem_fd.name,
                        node_name=node_name,
                        node_id=item.id,
                        id_attr=id_attr):
                    verified = True
                    break
            except XmlsecError as exc:
                logger.error('check_sig: %s', exc)
                pass
            except Exception as exc:
                logger.error('check_sig: %s', exc)
                raise

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1476,6 +1476,55 @@
         if not certs:
             raise MissingKey(_issuer)
 
+        # saml-core section "5.4 XML Signature Profile" defines constrains on the
+        # xmldsig-core facilities. It explicitly dictates that enveloped signatures
+        # are the only signatures allowed. This mean that:
+        # * Assertion/RequestType/ResponseType elements must have an ID attribute
+        # * signatures must have a single Reference element
+        # * the Reference element must have a URI attribute
+        # * the URI attribute contains an anchor
+        # * the anchor points to the enclosing element's ID attribute
+        references = item.signature.signed_info.reference
+        signatures_must_have_a_single_reference_element = len(references) == 1
+        the_Reference_element_must_have_a_URI_attribute = (
+            signatures_must_have_a_single_reference_element
+            and hasattr(references[0], "uri")
+        )
+        the_URI_attribute_contains_an_anchor = (
+            the_Reference_element_must_have_a_URI_attribute
+            and references[0].uri.startswith("#")
+            and len(references[0].uri) > 1
+        )
+        the_anchor_points_to_the_enclosing_element_ID_attribute = (
+            the_URI_attribute_contains_an_anchor
+            and references[0].uri == "#{id}".format(id=item.id)
+        )
+        validators = {
+            "signatures must have a single reference element": (
+                signatures_must_have_a_single_reference_element
+            ),
+            "the Reference element must have a URI attribute": (
+                the_Reference_element_must_have_a_URI_attribute
+            ),
+            "the URI attribute contains an anchor": (
+                the_URI_attribute_contains_an_anchor
+            ),
+            "the anchor points to the enclosing element ID attribute": (
+                the_anchor_points_to_the_enclosing_element_ID_attribute
+            ),
+        }
+        if not all(validators.values()):
+            error_context = {
+                "message": "Signature failed to meet constraints on xmldsig",
+                "validators": validators,
+                "item ID": item.id,
+                "reference URI": item.signature.signed_info.reference[0].uri,
+                "issuer": _issuer,
+                "node name": node_name,
+                "xml document": decoded_xml,
+            }
+            raise SignatureError(error_context)
+
         verified = False
         last_pem_file = None
 
```
