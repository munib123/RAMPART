# CrossVul Fix Pair: Improper Authentication in go
**Pair ID:** 4168_0
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4168_0`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```go
Lines 7-47 of the vulnerable file.

 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author		Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @Copyright 	2017-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @license 	Apache-2.0
 *
 */

package fosite

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/url"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
	jose "gopkg.in/square/go-jose.v2"
)

const clientAssertionJWTBearerType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

func (f *Fosite) findClientPublicJWK(oidcClient OpenIDConnectClient, t *jwt.Token) (interface{}, error) {
	if set := oidcClient.GetJSONWebKeys(); set != nil {
		return findPublicKey(t, set)
	}

	if location := oidcClient.GetJSONWebKeysURI(); len(location) > 0 {
		keys, err := f.JWKSFetcherStrategy.Resolve(location, false)
		if err != nil {
			return nil, err
		}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -24,9 +24,11 @@
 import (
 	"context"
 	"crypto/rsa"
+	"encoding/json"
 	"fmt"
 	"net/http"
 	"net/url"
+	"time"
 
 	jwt "github.com/dgrijalva/jwt-go"
 	"github.com/pkg/errors"
@@ -142,14 +144,36 @@
 			return nil, errors.WithStack(ErrInvalidClient.WithHint("Unable to type assert claims from request parameter \"client_assertion\".").WithDebugf(`Got claims of type %T but expected type "*jwt.MapClaims".`, token.Claims))
 		}
 
+		var jti string
 		if !claims.VerifyIssuer(clientID, true) {
 			return nil, errors.WithStack(ErrInvalidClient.WithHint("Claim \"iss\" from \"client_assertion\" must match the \"client_id\" of the OAuth 2.0 Client."))
 		} else if f.TokenURL == "" {
 			return nil, errors.WithStack(ErrMisconfiguration.WithHint("The authorization server's token endpoint URL has not been set."))
 		} else if sub, ok := (*claims)["sub"].(string); !ok || sub != clientID {
 			return nil, errors.WithStack(ErrInvalidClient.WithHint("Claim \"sub\" from \"client_assertion\" must match the \"client_id\" of the OAuth 2.0 Client."))
-		} else if jti, ok := (*claims)["jti"].(string); !ok || len(jti) == 0 {
+		} else if jti, ok = (*claims)["jti"].(string); !ok || len(jti) == 0 {
 			return nil, errors.WithStack(ErrInvalidClient.WithHint("Claim \"jti\" from \"client_assertion\" must be set but is not."))
+		} else if f.Store.ClientAssertionJWTValid(context.Background(), jti) != nil {
+			return nil, errors.WithStack(ErrJTIKnown.WithHint("Claim \"jti\" from \"client_assertion\" MUST only be used once."))
+		}
+
+		// type conversion according to jwt.MapClaims.VerifyExpiresAt
+		var expiry int64
+		err = nil
+		switch exp := (*claims)["exp"].(type) {
+		case float64:
+			expiry = int64(exp)
+		case json.Number:
+			expiry, err = exp.Int64()
+		default:
+			err = ErrInvalidClient.WithHint("Unable to type assert the expiry time from claims. This should not happen as we validate the expiry time already earlier with token.Claims.Valid()")
+		}
+
+		if err != nil {
+			return nil, errors.WithStack(err)
+		}
+		if err := f.Store.SetClientAssertionJWT(context.Background(), jti, time.Unix(expiry, 0)); err != nil {
+			return nil, err
 		}
 
 		if auds, ok := (*claims)["aud"].([]interface{}); !ok {
```
