# CrossVul Fix Pair: Insufficiently Protected Credentials in c
**Pair ID:** 3274_3
**Vulnerability Class:** Insufficiently Protected Credentials
**CWE:** CWE-522
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3274_3`)

## Vulnerability Information & PoC

## Description
Insufficiently Protected Credentials - The product transmits or stores authentication credentials, but it uses an insecure method that is susceptible to unauthorized interception and/or retrieval.

## Vulnerable Code
```c
Lines 25-49 of the vulnerable file.

// THE POSSIBILITY OF SUCH DAMAGE.
//**********************************************************************;

#ifndef SRC_TPM_KDFA_H_
#define SRC_TPM_KDFA_H_

#include <sapi/tpm20.h>

/* TODO DOCUMENT ME */
/**
 *
 * @param hashAlg
 * @param key
 * @param label
 * @param contextU
 * @param contextV
 * @param bits
 * @param resultKey
 * @return
 */
TPM_RC tpm_kdfa(TSS2_SYS_CONTEXT *sapi_context, TPMI_ALG_HASH hashAlg,
        TPM2B *key, char *label, TPM2B *contextU, TPM2B *contextV,
        UINT16 bits, TPM2B_MAX_BUFFER *resultKey );

#endif /* SRC_TPM_KDFA_H_ */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -42,7 +42,7 @@
  * @param resultKey
  * @return
  */
-TPM_RC tpm_kdfa(TSS2_SYS_CONTEXT *sapi_context, TPMI_ALG_HASH hashAlg,
+TPM_RC tpm_kdfa(TPMI_ALG_HASH hashAlg,
         TPM2B *key, char *label, TPM2B *contextU, TPM2B *contextV,
         UINT16 bits, TPM2B_MAX_BUFFER *resultKey );
 
```
