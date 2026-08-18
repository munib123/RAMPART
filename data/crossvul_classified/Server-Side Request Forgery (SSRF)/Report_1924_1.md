# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in go
**Pair ID:** 1924_1
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1924_1`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```go
Lines 3-43 of the vulnerable file.

 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cmd

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/klauspost/compress/zip"
	"github.com/minio/minio-go/v7"
	miniogo "github.com/minio/minio-go/v7"
	miniogopolicy "github.com/minio/minio-go/v7/pkg/policy"
	"github.com/minio/minio-go/v7/pkg/s3utils"
	"github.com/minio/minio/browser"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -20,7 +20,6 @@
 	"context"
 	"crypto/subtle"
 	"encoding/json"
-	"encoding/xml"
 	"errors"
 	"fmt"
 	"io"
@@ -2202,54 +2201,61 @@
 	Token string `json:"token" form:"token"`
 }
 
+var errSTSNotInitialized = errors.New("STS API not initialized, please configure STS support")
+
 // LoginSTS - STS user login handler.
 func (web *webAPIHandlers) LoginSTS(r *http.Request, args *LoginSTSArgs, reply *LoginRep) error {
 	ctx := newWebContext(r, args, "WebLoginSTS")
 
-	v := url.Values{}
-	v.Set("Action", webIdentity)
-	v.Set("WebIdentityToken", args.Token)
-	v.Set("Version", stsAPIVersion)
-
-	scheme := "http"
-	if sourceScheme := handlers.GetSourceScheme(r); sourceScheme != "" {
-		scheme = sourceScheme
-	}
-	if globalIsTLS {
-		scheme = "https"
-	}
-
-	u := &url.URL{
-		Scheme: scheme,
-		Host:   r.Host,
-	}
-
-	u.RawQuery = v.Encode()
-
-	req, err := http.NewRequest(http.MethodPost, u.String(), nil)
+	if globalOpenIDValidators == nil {
+		return toJSONError(ctx, errSTSNotInitialized)
+	}
+
+	v, err := globalOpenIDValidators.Get("jwt")
+	if err != nil {
+		logger.LogIf(ctx, err)
+		return toJSONError(ctx, errSTSNotInitialized)
+	}
+
+	m, err := v.Validate(args.Token, "")
 	if err != nil {
 		return toJSONError(ctx, err)
 	}
 
-	clnt := &http.Client{
-		Transport: NewGatewayHTTPTransport(),
-	}
-	resp, err := clnt.Do(req)
+	// JWT has requested a custom claim with policy value set.
+	// This is a MinIO STS API specific value, this value should
+	// be set and configured on your identity provider as part of
+	// JWT custom claims.
+	var policyName string
+	policySet, ok := iampolicy.GetPoliciesFromClaims(m, iamPolicyClaimNameOpenID())
+	if ok {
+		policyName = globalIAMSys.CurrentPolicies(strings.Join(policySet.ToSlice(), ","))
+	}
+	if policyName == "" && globalPolicyOPA == nil {
+		return toJSONError(ctx, fmt.Errorf("%s claim missing from the JWT token, credentials will not be generated", iamPolicyClaimNameOpenID()))
+	}
+	m[iamPolicyClaimNameOpenID()] = policyName
+
+	secret := globalActiveCred.SecretKey
+	cred, err := auth.GetNewCredentialsWithMetadata(m, secret)
 	if err != nil {
 		return toJSONError(ctx, err)
 	}
-	defer xhttp.DrainBody(resp.Body)
-
-	if resp.StatusCode != http.StatusOK {
-		return toJSONError(ctx, errors.New(resp.Status))
-	}
-
-	a := AssumeRoleWithWebIdentityResponse{}
-	if err = xml.NewDecoder(resp.Body).Decode(&a); err != nil {
+
+	// Set the newly generated credentials.
+	if err = globalIAMSys.SetTempUser(cred.AccessKey, cred, policyName); err != nil {
 		return toJSONError(ctx, err)
 	}
 
-	reply.Token = a.Result.Credentials.SessionToken
+	// Notify all other MinIO peers to reload temp users
+	for _, nerr := range globalNotificationSys.LoadUser(cred.AccessKey, true) {
+		if nerr.Err != nil {
+			logger.GetReqInfo(ctx).SetTags("peerAddress", nerr.Host.String())
+			logger.LogIf(ctx, nerr.Err)
+		}
+	}
+
+	reply.Token = cred.SessionToken
 	reply.UIVersion = browser.UIVersion
 	return nil
 }
@@ -2304,6 +2310,8 @@
 			HTTPStatusCode: http.StatusBadRequest,
 			Description:    err.Error(),
 		}
+	case errSTSNotInitialized:
+		return APIError(stsErrCodes.ToSTSErr(ErrSTSNotInitialized))
 	case errServerNotInitialized:
 		return APIError{
 			Code:           "XMinioServerNotInitialized",
```
