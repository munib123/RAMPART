# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 1533_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1533_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 25-65 of the vulnerable file.

 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "k5-int.h"
#include "k5-json.h"
#include <krb5/preauth_plugin.h>
#include "otp_state.h"

#include <errno.h>
#include <ctype.h>

static krb5_preauthtype otp_pa_type_list[] =
  { KRB5_PADATA_OTP_REQUEST, 0 };

struct request_state {
    krb5_kdcpreauth_verify_respond_fn respond;
    void *arg;
};

static krb5_error_code
decrypt_encdata(krb5_context context, krb5_keyblock *armor_key,
                krb5_pa_otp_req *req, krb5_data *out)
{
    krb5_error_code retval;
    krb5_data plaintext;

    if (req == NULL)
        return EINVAL;

    retval = alloc_data(&plaintext, req->enc_data.ciphertext.length);
    if (retval)
        return retval;

    retval = krb5_c_decrypt(context, armor_key, KRB5_KEYUSAGE_PA_OTP_REQUEST,
                            NULL, &req->enc_data, &plaintext);
    if (retval != 0) {
        com_err("otp", retval, "Unable to decrypt encData in PA-OTP-REQUEST");
        free(plaintext.data);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -42,6 +42,7 @@
 struct request_state {
     krb5_kdcpreauth_verify_respond_fn respond;
     void *arg;
+    krb5_enc_tkt_part *enc_tkt_reply;
 };
 
 static krb5_error_code
@@ -158,6 +159,9 @@
 
     if (retval == 0 && response != otp_response_success)
         retval = KRB5_PREAUTH_FAILED;
+
+    if (retval == 0)
+        rs.enc_tkt_reply->flags |= TKT_FLG_PRE_AUTH;
 
     rs.respond(rs.arg, retval, NULL, NULL, NULL);
 }
@@ -263,8 +267,6 @@
     krb5_data d, plaintext;
     char *config;
 
-    enc_tkt_reply->flags |= TKT_FLG_PRE_AUTH;
-
     /* Get the FAST armor key. */
     armor_key = cb->fast_armor(context, rock);
     if (armor_key == NULL) {
@@ -298,12 +300,14 @@
         goto error;
     }
 
-    /* Create the request state. */
+    /* Create the request state.  Save the response callback, and the
+     * enc_tkt_reply pointer so we can set the TKT_FLG_PRE_AUTH flag later. */
     rs = k5alloc(sizeof(struct request_state), &retval);
     if (rs == NULL)
         goto error;
     rs->arg = arg;
     rs->respond = respond;
+    rs->enc_tkt_reply = enc_tkt_reply;
 
     /* Get the principal's OTP configuration string. */
     retval = cb->get_string(context, rock, "otp", &config);
```
