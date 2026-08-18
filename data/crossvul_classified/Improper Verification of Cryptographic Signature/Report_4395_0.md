# CrossVul Fix Pair: Improper Verification of Cryptographic Signature in go
**Pair ID:** 4395_0
**Vulnerability Class:** Improper Verification of Cryptographic Signature
**CWE:** CWE-347
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4395_0`)

## Vulnerability Information & PoC

## Description
Improper Verification of Cryptographic Signature - The product does not verify, or incorrectly verifies, the cryptographic signature for data.

## Vulnerable Code
```go
Lines 1-30 of the vulnerable file.

// Package saml contains login methods for SAML.
package saml

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"
	"sync"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/pkg/groups"
	"github.com/dexidp/dex/pkg/log"
)

// nolint
const (
	bindingRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	bindingPOST     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -7,7 +7,6 @@
 	"encoding/base64"
 	"encoding/pem"
 	"encoding/xml"
-	"errors"
 	"fmt"
 	"io/ioutil"
 	"strings"
@@ -15,6 +14,8 @@
 	"time"
 
 	"github.com/beevik/etree"
+	xrv "github.com/mattermost/xml-roundtrip-validator"
+	"github.com/pkg/errors"
 	dsig "github.com/russellhaering/goxmldsig"
 	"github.com/russellhaering/goxmldsig/etreeutils"
 
@@ -287,6 +288,7 @@
 //
 // The steps taken are:
 //
+// * Validate XML document does not contain malicious inputs.
 // * Verify signature on XML document (or verify sig on assertion elements).
 // * Verify various parts of the Assertion element. Conditions, audience, etc.
 // * Map the Assertion's attribute elements to user info.
@@ -295,6 +297,11 @@
 	rawResp, err := base64.StdEncoding.DecodeString(samlResponse)
 	if err != nil {
 		return ident, fmt.Errorf("decode response: %v", err)
+	}
+
+	byteReader := bytes.NewReader(rawResp)
+	if xrvErr := xrv.Validate(byteReader); xrvErr != nil {
+		return ident, errors.Wrap(xrvErr, "validating XML response")
 	}
 
 	// Root element is allowed to not be signed if the Assertion element is.
```
