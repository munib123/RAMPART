# CrossVul Fix Pair: Allocation of File Descriptors or Handles Without Limits or Throttling in go
**Pair ID:** 39_0
**Vulnerability Class:** Allocation of File Descriptors or Handles Without Limits or Throttling
**CWE:** CWE-774
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `39_0`)

## Vulnerability Information & PoC

## Description
Allocation of File Descriptors or Handles Without Limits or Throttling - This can cause the product to consume all available file descriptors or handles, which can prevent other processes from performing critical file processing operations.

## Vulnerable Code
```go
Lines 11-51 of the vulnerable file.

 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/minio/minio/cmd/logger"
	"github.com/minio/minio/pkg/policy"
)

// Verify if request has JWT.
func isRequestJWT(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get("Authorization"), jwtAlgorithm)
}

// Verify if request has AWS Signature Version '4'.
func isRequestSignatureV4(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get("Authorization"), signV4Algorithm)
}

// Verify if request has AWS Signature Version '2'.
func isRequestSignatureV2(r *http.Request) bool {
	return (!strings.HasPrefix(r.Header.Get("Authorization"), signV4Algorithm) &&
		strings.HasPrefix(r.Header.Get("Authorization"), signV2Algorithm))
}

// Verify if request has AWS PreSign Version '4'.
func isRequestPresignedSignatureV4(r *http.Request) bool {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -28,6 +28,7 @@
 	"strings"
 
 	"github.com/minio/minio/cmd/logger"
+	"github.com/minio/minio/pkg/hash"
 	"github.com/minio/minio/pkg/policy"
 )
 
@@ -209,59 +210,45 @@
 
 // Verify if request has valid AWS Signature Version '4'.
 func isReqAuthenticated(r *http.Request, region string) (s3Error APIErrorCode) {
-	if r == nil {
-		return ErrInternalError
-	}
-
 	if errCode := reqSignatureV4Verify(r, region); errCode != ErrNone {
 		return errCode
 	}
 
-	payload, err := ioutil.ReadAll(r.Body)
+	var (
+		err                       error
+		contentMD5, contentSHA256 []byte
+	)
+	// Extract 'Content-Md5' if present.
+	if _, ok := r.Header["Content-Md5"]; ok {
+		contentMD5, err = base64.StdEncoding.Strict().DecodeString(r.Header.Get("Content-Md5"))
+		if err != nil || len(contentMD5) == 0 {
+			return ErrInvalidDigest
+		}
+	}
+
+	// Extract either 'X-Amz-Content-Sha256' header or 'X-Amz-Content-Sha256' query parameter (if V4 presigned)
+	// Do not verify 'X-Amz-Content-Sha256' if skipSHA256.
+	if skipSHA256 := skipContentSha256Cksum(r); !skipSHA256 && isRequestPresignedSignatureV4(r) {
+		if sha256Sum, ok := r.URL.Query()["X-Amz-Content-Sha256"]; ok && len(sha256Sum) > 0 {
+			contentSHA256, err = hex.DecodeString(sha256Sum[0])
+			if err != nil {
+				return ErrContentSHA256Mismatch
+			}
+		}
+	} else if _, ok := r.Header["X-Amz-Content-Sha256"]; !skipSHA256 && ok {
+		contentSHA256, err = hex.DecodeString(r.Header.Get("X-Amz-Content-Sha256"))
+		if err != nil || len(contentSHA256) == 0 {
+			return ErrContentSHA256Mismatch
+		}
+	}
+
+	// Verify 'Content-Md5' and/or 'X-Amz-Content-Sha256' if present.
+	// The verification happens implicit during reading.
+	reader, err := hash.NewReader(r.Body, -1, hex.EncodeToString(contentMD5), hex.EncodeToString(contentSHA256))
 	if err != nil {
-		logger.LogIf(context.Background(), err)
-		return ErrInternalError
-	}
-
-	// Populate back the payload.
-	r.Body = ioutil.NopCloser(bytes.NewReader(payload))
-
-	// Verify Content-Md5, if payload is set.
-	if clntMD5B64, ok := r.Header["Content-Md5"]; ok {
-		if clntMD5B64[0] == "" {
-			return ErrInvalidDigest
-		}
-		md5Sum, err := base64.StdEncoding.Strict().DecodeString(clntMD5B64[0])
-		if err != nil {
-			return ErrInvalidDigest
-		}
-		if !bytes.Equal(md5Sum, getMD5Sum(payload)) {
-			return ErrBadDigest
-		}
-	}
-
-	if skipContentSha256Cksum(r) {
-		return ErrNone
-	}
-
-	// Verify that X-Amz-Content-Sha256 Header == sha256(payload)
-	// If X-Amz-Content-Sha256 header is not sent then we don't calculate/verify sha256(payload)
-	sumHex, ok := r.Header["X-Amz-Content-Sha256"]
-	if isRequestPresignedSignatureV4(r) {
-		sumHex, ok = r.URL.Query()["X-Amz-Content-Sha256"]
-	}
-	if ok {
-		if sumHex[0] == "" {
-			return ErrContentSHA256Mismatch
-		}
-		sum, err := hex.DecodeString(sumHex[0])
-		if err != nil {
-			return ErrContentSHA256Mismatch
-		}
-		if !bytes.Equal(sum, getSHA256Sum(payload)) {
-			return ErrContentSHA256Mismatch
-		}
-	}
+		return toAPIErrorCode(err)
+	}
+	r.Body = ioutil.NopCloser(reader)
 	return ErrNone
 }
 
```
