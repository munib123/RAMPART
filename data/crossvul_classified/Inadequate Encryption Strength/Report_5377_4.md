# CrossVul Fix Pair: Inadequate Encryption Strength in go
**Pair ID:** 5377_4
**Vulnerability Class:** Inadequate Encryption Strength
**CWE:** CWE-326
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5377_4`)

## Vulnerability Information & PoC

## Description
Inadequate Encryption Strength - A weak encryption scheme can be subjected to brute force attacks that have a reasonable chance of succeeding using current attack methods and resources.

## Vulnerable Code
```go
Lines 6-46 of the vulnerable file.

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

package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"
	"reflect"
	"strings"

	"github.com/square/go-jose/json"
)

// rawJsonWebKey represents a public or private key in JWK format, used for parsing/serializing.
type rawJsonWebKey struct {
	Use string      `json:"use,omitempty"`
	Kty string      `json:"kty,omitempty"`
	Kid string      `json:"kid,omitempty"`
	Crv string      `json:"crv,omitempty"`
	Alg string      `json:"alg,omitempty"`
	K   *byteBuffer `json:"k,omitempty"`
	X   *byteBuffer `json:"x,omitempty"`
	Y   *byteBuffer `json:"y,omitempty"`
	N   *byteBuffer `json:"n,omitempty"`
	E   *byteBuffer `json:"e,omitempty"`
	// -- Following fields are only used for private keys --
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -23,6 +23,7 @@
 	"crypto/rsa"
 	"crypto/x509"
 	"encoding/base64"
+	"errors"
 	"fmt"
 	"math/big"
 	"reflect"
@@ -277,13 +278,20 @@
 	}
 
 	if key.X == nil || key.Y == nil {
-		return nil, fmt.Errorf("square/go-jose: invalid EC key, missing x/y values")
+		return nil, errors.New("square/go-jose: invalid EC key, missing x/y values")
+	}
+
+	x := key.X.bigInt()
+	y := key.Y.bigInt()
+
+	if !curve.IsOnCurve(x, y) {
+		return nil, errors.New("square/go-jose: invalid EC key, X/Y are not on declared curve")
 	}
 
 	return &ecdsa.PublicKey{
 		Curve: curve,
-		X:     key.X.bigInt(),
-		Y:     key.Y.bigInt(),
+		X:     x,
+		Y:     y,
 	}, nil
 }
 
```
