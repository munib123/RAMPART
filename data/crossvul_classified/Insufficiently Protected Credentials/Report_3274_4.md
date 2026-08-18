# CrossVul Fix Pair: Insufficiently Protected Credentials in c
**Pair ID:** 3274_4
**Vulnerability Class:** Insufficiently Protected Credentials
**CWE:** CWE-522
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3274_4`)

## Vulnerability Information & PoC

## Description
Insufficiently Protected Credentials - The product transmits or stores authentication credentials, but it uses an insecure method that is susceptible to unauthorized interception and/or retrieval.

## Vulnerable Code
```c
Lines 181-221 of the vulnerable file.

            bool result = string_bytes_concat_buffer( (TPM2B_MAX_BUFFER *)&key, &( session->authValueBind.b ) );
            if (!result)
            {
               return TSS2_SYS_RC_BAD_VALUE;
            }

            result = string_bytes_concat_buffer( (TPM2B_MAX_BUFFER *)&key, &( session->salt.b ) );
            if (!result)
            {
                return TSS2_SYS_RC_BAD_VALUE;
            }

            bytes = GetDigestSize( session->authHash );

            if( key.t.size == 0 )
            {
                session->sessionKey.t.size = 0;
            }
            else
            {
                rval = tpm_kdfa(sapi_context, session->authHash, &(key.b), label, &( session->nonceNewer.b ),
                        &( session->nonceOlder.b ), bytes * 8, (TPM2B_MAX_BUFFER *)&( session->sessionKey ) );
            }

            if( rval != TPM_RC_SUCCESS )
            {
                return( TSS2_APP_RC_CREATE_SESSION_KEY_FAILED );
            }
        }

        session->nonceTpmDecrypt.b.size = 0;
        session->nonceTpmEncrypt.b.size = 0;
        session->nvNameChanged = 0;
    }

    return rval;
}

TPM_RC tpm_session_auth_end( SESSION *session )
{
    TPM_RC rval = TPM_RC_SUCCESS;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -198,7 +198,7 @@
             }
             else
             {
-                rval = tpm_kdfa(sapi_context, session->authHash, &(key.b), label, &( session->nonceNewer.b ),
+                rval = tpm_kdfa(session->authHash, &(key.b), label, &( session->nonceNewer.b ),
                         &( session->nonceOlder.b ), bytes * 8, (TPM2B_MAX_BUFFER *)&( session->sessionKey ) );
             }
 
```
