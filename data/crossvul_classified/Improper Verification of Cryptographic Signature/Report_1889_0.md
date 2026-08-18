# CrossVul Fix Pair: Improper Verification of Cryptographic Signature in python
**Pair ID:** 1889_0
**Vulnerability Class:** Improper Verification of Cryptographic Signature
**CWE:** CWE-347
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1889_0`)

## Vulnerability Information & PoC

## Description
Improper Verification of Cryptographic Signature - The product does not verify, or incorrectly verifies, the cryptographic signature for data.

## Vulnerable Code
```python
Lines 852-892 of the vulnerable file.


        :param signedtext: The XML document as a string
        :param cert_file: The public key that was used to sign the document
        :param cert_type: The file type of the certificate
        :param node_name: The name of the class that is signed
        :param node_id: The identifier of the node
        :return: Boolean True if the signature was correct otherwise False.
        """
        if not isinstance(signedtext, six.binary_type):
            signedtext = signedtext.encode('utf-8')

        tmp = make_temp(signedtext,
                        suffix=".xml",
                        decode=False,
                        delete_tmpfiles=self.delete_tmpfiles)

        com_list = [
            self.xmlsec,
            '--verify',
            '--enabled-reference-uris', 'empty,same-doc',
            '--pubkey-cert-{type}'.format(type=cert_type), cert_file,
            '--id-attr:ID', node_name,
        ]

        if node_id:
            com_list.extend(['--node-id', node_id])

        try:
            (_stdout, stderr, _output) = self._run_xmlsec(com_list, [tmp.name])
        except XmlsecError as e:
            six.raise_from(SignatureError(com_list), e)

        return parse_xmlsec_output(stderr)

    def _run_xmlsec(self, com_list, extra_args):
        """
        Common code to invoke xmlsec and parse the output.
        :param com_list: Key-value parameter list for xmlsec
        :param extra_args: Positional parameters to be appended after all
            key-value parameters
        :result: Whatever xmlsec wrote to an --output temporary file
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -869,6 +869,7 @@
             self.xmlsec,
             '--verify',
             '--enabled-reference-uris', 'empty,same-doc',
+            '--enabled-key-data', 'raw-x509-cert',
             '--pubkey-cert-{type}'.format(type=cert_type), cert_file,
             '--id-attr:ID', node_name,
         ]
```
