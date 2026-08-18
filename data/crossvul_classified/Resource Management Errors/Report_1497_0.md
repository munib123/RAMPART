# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 1497_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1497_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 43-83 of the vulnerable file.

 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#include "cryptlib.h"
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/cms.h>
#include "cms_lcl.h"
#include "asn1_locl.h"

static int cms_copy_content(BIO *out, BIO *in, unsigned int flags)
	{
	unsigned char buf[4096];
	int r = 0, i;
	BIO *tmpout = NULL;

	if (out == NULL)
		tmpout = BIO_new(BIO_s_null());
	else if (flags & CMS_TEXT)
		{
		tmpout = BIO_new(BIO_s_mem());
		BIO_set_mem_eof_return(tmpout, 0);
		}
	else
		tmpout = out;

	if(!tmpout)
		{
		CMSerr(CMS_F_CMS_COPY_CONTENT,ERR_R_MALLOC_FAILURE);
		goto err;
		}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -60,21 +60,28 @@
 #include "cms_lcl.h"
 #include "asn1_locl.h"
 
+static BIO *cms_get_text_bio(BIO *out, unsigned int flags)
+	{
+	BIO *rbio;
+	if (out == NULL)
+		rbio = BIO_new(BIO_s_null());
+	else if (flags & CMS_TEXT)
+		{
+		rbio = BIO_new(BIO_s_mem());
+		BIO_set_mem_eof_return(rbio, 0);
+		}
+	else
+		rbio = out;
+	return rbio;
+	}
+
 static int cms_copy_content(BIO *out, BIO *in, unsigned int flags)
 	{
 	unsigned char buf[4096];
 	int r = 0, i;
-	BIO *tmpout = NULL;
-
-	if (out == NULL)
-		tmpout = BIO_new(BIO_s_null());
-	else if (flags & CMS_TEXT)
-		{
-		tmpout = BIO_new(BIO_s_mem());
-		BIO_set_mem_eof_return(tmpout, 0);
-		}
-	else
-		tmpout = out;
+	BIO *tmpout;
+
+	tmpout = cms_get_text_bio(out, flags);
 
 	if(!tmpout)
 		{
@@ -142,7 +149,7 @@
 			BIO_free(f);
 			f = tbio;
 			}
-		while (f != upto);
+		while (f && f != upto);
 		}
 	else
 		BIO_free_all(f);
@@ -323,7 +330,7 @@
 	STACK_OF(X509_CRL) *crls = NULL;
 	X509 *signer;
 	int i, scount = 0, ret = 0;
-	BIO *cmsbio = NULL, *tmpin = NULL;
+	BIO *cmsbio = NULL, *tmpin = NULL, *tmpout = NULL;
 
 	if (!dcont && !check_content(cms))
 		return 0;
@@ -406,15 +413,48 @@
 		}
 	else
 		tmpin = dcont;
-		
-
-	cmsbio=CMS_dataInit(cms, tmpin);
-	if (!cmsbio)
-		goto err;
-
-	if (!cms_copy_content(out, cmsbio, flags))
-		goto err;
-
+	/* If not binary mode and detached generate digests by *writing*
+	 * through the BIO. That makes it possible to canonicalise the
+	 * input.
+	 */
+	if (!(flags & SMIME_BINARY) && dcont)
+		{
+		/* Create output BIO so we can either handle text or to
+		 * ensure included content doesn't override detached content.
+		 */
+		tmpout = cms_get_text_bio(out, flags);
+		if(!tmpout)
+			{
+			CMSerr(CMS_F_CMS_VERIFY,ERR_R_MALLOC_FAILURE);
+			goto err;
+			}
+		cmsbio = CMS_dataInit(cms, tmpout);
+		if (!cmsbio)
+			goto err;
+		/* Don't use SMIME_TEXT for verify: it adds headers and
+		 * we want to remove them.
+		 */
+		SMIME_crlf_copy(dcont, cmsbio, flags & ~SMIME_TEXT);
+
+		if(flags & CMS_TEXT)
+			{
+			if (!SMIME_text(tmpout, out))
+				{
+				CMSerr(CMS_F_CMS_VERIFY,CMS_R_SMIME_TEXT_ERROR);
+				goto err;
+				}
+			}
+		}
+	else
+		{
+		cmsbio=CMS_dataInit(cms, tmpin);
+		if (!cmsbio)
+			goto err;
+
+		if (!cms_copy_content(out, cmsbio, flags))
+			goto err;
+
+		}
 	if (!(flags & CMS_NO_CONTENT_VERIFY))
 		{
 		for (i = 0; i < sk_CMS_SignerInfo_num(sinfos); i++)
@@ -432,11 +472,23 @@
 	ret = 1;
 
 	err:
-	
-	if (dcont && (tmpin == dcont))
-		do_free_upto(cmsbio, dcont);
+	if (!(flags & SMIME_BINARY) && dcont)
+		{
+		do_free_upto(cmsbio, tmpout);
+		if (tmpin != dcont)
+			BIO_free(tmpin);
+		}
 	else
-		BIO_free_all(cmsbio);
+		{
+
+		if (dcont && (tmpin == dcont))
+			do_free_upto(cmsbio, dcont);
+		else
+			BIO_free_all(cmsbio);
+		}
+
+	if (tmpout && out != tmpout)
+		BIO_free_all(tmpout);
 
 	if (cms_certs)
 		sk_X509_pop_free(cms_certs, X509_free);
```
