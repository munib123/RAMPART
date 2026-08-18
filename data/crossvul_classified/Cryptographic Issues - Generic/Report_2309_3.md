# CrossVul Fix Pair: Cryptographic Issues in c
**Pair ID:** 2309_3
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2309_3`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```c
Lines 40-80 of the vulnerable file.

 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include "ecs_locl.h"
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif

/*-
 * returns
 *      1: correct signature
 *      0: incorrect signature
 *     -1: error
 */
int ECDSA_do_verify(const unsigned char *dgst, int dgst_len, 
		const ECDSA_SIG *sig, EC_KEY *eckey)
	{
	ECDSA_DATA *ecdsa = ecdsa_check(eckey);
	if (ecdsa == NULL)
		return 0;
	return ecdsa->meth->ecdsa_do_verify(dgst, dgst_len, sig, eckey);
	}

/*-
 * returns
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -57,6 +57,7 @@
  */
 
 #include "ecs_locl.h"
+#include "cryptlib.h"
 #ifndef OPENSSL_NO_ENGINE
 #include <openssl/engine.h>
 #endif
@@ -86,13 +87,25 @@
 		const unsigned char *sigbuf, int sig_len, EC_KEY *eckey)
  	{
 	ECDSA_SIG *s;
+	const unsigned char *p = sigbuf;
+	unsigned char *der = NULL;
+	int derlen = -1;
 	int ret=-1;
 
 	s = ECDSA_SIG_new();
 	if (s == NULL) return(ret);
-	if (d2i_ECDSA_SIG(&s, &sigbuf, sig_len) == NULL) goto err;
+	if (d2i_ECDSA_SIG(&s, &p, sig_len) == NULL) goto err;
+	/* Ensure signature uses DER and doesn't have trailing garbage */
+	derlen = i2d_ECDSA_SIG(s, &der);
+	if (derlen != sig_len || memcmp(sigbuf, der, derlen))
+		goto err;
 	ret=ECDSA_do_verify(dgst, dgst_len, s, eckey);
 err:
+	if (derlen > 0)
+		{
+		OPENSSL_cleanse(der, derlen);
+		OPENSSL_free(der);
+		}
 	ECDSA_SIG_free(s);
 	return(ret);
 	}
```
