# CrossVul Fix Pair: Improper Handling of Exceptional Conditions in go
**Pair ID:** 4169_9
**Vulnerability Class:** Improper Handling of Exceptional Conditions
**CWE:** CWE-755
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4169_9`)

## Vulnerability Information & PoC

## Description
Improper Handling of Exceptional Conditions - The product does not handle or incorrectly handles an exceptional condition.

## Vulnerable Code
```go
Lines 22-62 of the vulnerable file.

package openid

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"

	"github.com/ory/fosite"
)

type IDTokenHandleHelper struct {
	IDTokenStrategy OpenIDConnectTokenStrategy
}

func (i *IDTokenHandleHelper) GetAccessTokenHash(ctx context.Context, requester fosite.AccessRequester, responder fosite.AccessResponder) string {
	token := responder.GetAccessToken()

	buffer := bytes.NewBufferString(token)
	hash := sha256.New()
	hash.Write(buffer.Bytes())
	hashBuf := bytes.NewBuffer(hash.Sum([]byte{}))
	len := hashBuf.Len()

	return base64.RawURLEncoding.EncodeToString(hashBuf.Bytes()[:len/2])
}

func (i *IDTokenHandleHelper) generateIDToken(ctx context.Context, fosr fosite.Requester) (token string, err error) {
	token, err = i.IDTokenStrategy.GenerateIDToken(ctx, fosr)
	if err != nil {
		return "", err
	}

	return token, nil
}

func (i *IDTokenHandleHelper) IssueImplicitIDToken(ctx context.Context, ar fosite.Requester, resp fosite.AuthorizeResponder) error {
	token, err := i.generateIDToken(ctx, ar)
	if err != nil {
		return err
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -39,7 +39,11 @@
 
 	buffer := bytes.NewBufferString(token)
 	hash := sha256.New()
-	hash.Write(buffer.Bytes())
+	// sha256.digest.Write() always returns nil for err, the panic should never happen
+	_, err := hash.Write(buffer.Bytes())
+	if err != nil {
+		panic(err)
+	}
 	hashBuf := bytes.NewBuffer(hash.Sum([]byte{}))
 	len := hashBuf.Len()
 
```
