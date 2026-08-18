# CrossVul Fix Pair: Authentication Bypass by Spoofing in go
**Pair ID:** 4387_2
**Vulnerability Class:** Authentication Bypass
**CWE:** CWE-290
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4387_2`)

## Vulnerability Information & PoC

## Description
Authentication Bypass by Spoofing - This attack-focused weakness is caused by incorrectly implemented authentication schemes that are subject to spoofing attacks.

## Vulnerable Code
```go
Lines 1-24 of the vulnerable file.

package sso

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/fleetdm/fleet/server/kolide"
	"github.com/pkg/errors"
	gosamltypes "github.com/russellhaering/gosaml2/types"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"
)

type Validator interface {
	ValidateSignature(auth kolide.Auth) (kolide.Auth, error)
	ValidateResponse(auth kolide.Auth) error
}

type validator struct {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,7 @@
 package sso
 
 import (
+	"bytes"
 	"crypto/rand"
 	"crypto/x509"
 	"encoding/base64"
@@ -10,6 +11,7 @@
 
 	"github.com/beevik/etree"
 	"github.com/fleetdm/fleet/server/kolide"
+	rtvalidator "github.com/mattermost/xml-roundtrip-validator"
 	"github.com/pkg/errors"
 	gosamltypes "github.com/russellhaering/gosaml2/types"
 	dsig "github.com/russellhaering/goxmldsig"
@@ -103,8 +105,16 @@
 	}
 	decoded, err := base64.StdEncoding.DecodeString(info.rawResponse())
 	if err != nil {
-		return nil, errors.Wrap(err, "based64 decoding response")
-	}
+		return nil, errors.Wrap(err, "base64 decode response")
+	}
+
+	// Examine the response for attempts to exploit weaknesses in Go's
+	// encoding/xml
+	err = rtvalidator.Validate(bytes.NewReader(decoded))
+	if err != nil {
+		return nil, errors.Wrap(err, "response XML failed validation")
+	}
+
 	doc := etree.NewDocument()
 	err = doc.ReadFromBytes(decoded)
 	if err != nil || doc.Root() == nil {
```
