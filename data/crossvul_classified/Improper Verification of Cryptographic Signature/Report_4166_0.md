# CrossVul Fix Pair: Improper Verification of Cryptographic Signature in go
**Pair ID:** 4166_0
**Vulnerability Class:** Improper Verification of Cryptographic Signature
**CWE:** CWE-347
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4166_0`)

## Vulnerability Information & PoC

## Description
Improper Verification of Cryptographic Signature - The product does not verify, or incorrectly verifies, the cryptographic signature for data.

## Vulnerable Code
```go
Lines 4-44 of the vulnerable file.

	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"

	"github.com/beevik/etree"
	"github.com/russellhaering/goxmldsig/etreeutils"
	"github.com/russellhaering/goxmldsig/types"
)

var uriRegexp = regexp.MustCompile("^#[a-zA-Z_][\\w.-]*$")
var whiteSpace = regexp.MustCompile("\\s+")

var (
	// ErrMissingSignature indicates that no enveloped signature was found referencing
	// the top level element passed for signature verification.
	ErrMissingSignature = errors.New("Missing signature referencing the top-level element")
)

type ValidationContext struct {
	CertificateStore X509CertificateStore
	IdAttribute      string
	Clock            *Clock
}

func NewDefaultValidationContext(certificateStore X509CertificateStore) *ValidationContext {
	return &ValidationContext{
		CertificateStore: certificateStore,
		IdAttribute:      DefaultIdAttr,
	}
}

// TODO(russell_h): More flexible namespace support. This might barely work.
func inNamespace(el *etree.Element, ns string) bool {
	for _, attr := range el.Attr {
		if attr.Value == ns {
			if attr.Space == "" && attr.Key == "xmlns" {
				return el.Space == ""
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -21,6 +21,7 @@
 	// ErrMissingSignature indicates that no enveloped signature was found referencing
 	// the top level element passed for signature verification.
 	ErrMissingSignature = errors.New("Missing signature referencing the top-level element")
+	ErrInvalidSignature = errors.New( "Invalid Signature")
 )
 
 type ValidationContext struct {
@@ -296,9 +297,28 @@
 	return false
 }
 
+// In most places, we use etree Elements, but while deserializing the Signature, we use
+// encoding/xml unmarshal directly to convert to a convenient go struct. This presents a problem in some cases because
+// when an xml element repeats under the parent, the last element will win and/or be appended. We need to assert that
+// the Signature object matches the expected shape of a Signature object.
+func validateShape(signatureEl *etree.Element) error {
+	children := signatureEl.ChildElements()
+
+	childCounts := map[string]int{}
+	for _, child := range children {
+		childCounts[child.Tag]++
+	}
+
+	validateCount := childCounts[SignedInfoTag] == 1 && childCounts[KeyInfoTag] <= 1 && childCounts[SignatureValueTag] == 1
+	if !validateCount {
+		return ErrInvalidSignature
+	}
+	return nil
+}
+
 // findSignature searches for a Signature element referencing the passed root element.
-func (ctx *ValidationContext) findSignature(el *etree.Element) (*types.Signature, error) {
-	idAttr := el.SelectAttr(ctx.IdAttribute)
+func (ctx *ValidationContext) findSignature(root *etree.Element) (*types.Signature, error) {
+	idAttr := root.SelectAttr(ctx.IdAttribute)
 	if idAttr == nil || idAttr.Value == "" {
 		return nil, errors.New("Missing ID attribute")
 	}
@@ -306,10 +326,13 @@
 	var sig *types.Signature
 
 	// Traverse the tree looking for a Signature element
-	err := etreeutils.NSFindIterate(el, Namespace, SignatureTag, func(ctx etreeutils.NSContext, el *etree.Element) error {
-
+	err := etreeutils.NSFindIterate(root, Namespace, SignatureTag, func(ctx etreeutils.NSContext, signatureEl *etree.Element) error {
+		err := validateShape(signatureEl)
+		if err != nil {
+			return err
+		}
 		found := false
-		err := etreeutils.NSFindChildrenIterateCtx(ctx, el, Namespace, SignedInfoTag,
+		err = etreeutils.NSFindChildrenIterateCtx(ctx, signatureEl, Namespace, SignedInfoTag,
 			func(ctx etreeutils.NSContext, signedInfo *etree.Element) error {
 				detachedSignedInfo, err := etreeutils.NSDetatch(ctx, signedInfo)
 				if err != nil {
@@ -355,8 +378,8 @@
 					return fmt.Errorf("invalid CanonicalizationMethod on Signature: %s", c14NAlgorithm)
 				}
 
-				el.RemoveChild(signedInfo)
-				el.AddChild(canonicalSignedInfo)
+				signatureEl.RemoveChild(signedInfo)
+				signatureEl.AddChild(canonicalSignedInfo)
 
 				found = true
 
@@ -372,7 +395,7 @@
 
 		// Unmarshal the signature into a structured Signature type
 		_sig := &types.Signature{}
-		err = etreeutils.NSUnmarshalElement(ctx, el, _sig)
+		err = etreeutils.NSUnmarshalElement(ctx, signatureEl, _sig)
 		if err != nil {
 			return err
 		}
```
