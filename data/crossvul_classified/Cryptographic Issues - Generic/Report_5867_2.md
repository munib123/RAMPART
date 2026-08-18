# CrossVul Fix Pair: Cryptographic Issues in c
**Pair ID:** 5867_2
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5867_2`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```c
Lines 35-75 of the vulnerable file.

    int rsa_tmp_bits;
};

struct chiper_info {
    char version[16];
    char chiper[48];
    int chiper_bits;
};

SSL_CTX *_SSL_context_init (void (*info_cb_func), int server);
#define _SSL_context_free(a)	SSL_CTX_free(a);

SSL *_SSL_socket (SSL_CTX *ctx, int sd);
char *_SSL_set_verify (SSL_CTX *ctx, void *(verify_callback), char *cacert);
/*
    int SSL_connect(SSL *);
    int SSL_accept(SSL *);
    int SSL_get_fd(SSL *);
*/
void _SSL_close (SSL * ssl);

int _SSL_get_cert_info (struct cert_info *cert_info, SSL * ssl);
struct chiper_info *_SSL_get_cipher_info (SSL * ssl);

/*char *_SSL_add_keypair (SSL_CTX *ctx, char *privkey, char *cert);*/
/*void _SSL_add_random_keypair(SSL_CTX *ctx, int bits);*/

int _SSL_send (SSL * ssl, char *buf, int len);
int _SSL_recv (SSL * ssl, char *buf, int len);

/* misc */
/*void broke_oneline (char *oneline, char *parray[]);*/

/*char *_SSL_do_cipher_base64(char *buf, int buf_len, char *key, int operation);*/		/* must be freed */

/*void *_SSL_get_sess_obj(SSL *ssl, int type);*/		/* NOT must be freed */
#define	_SSL_get_sess_pkey(a)	_SSL_get_sess_obj(a, 0)
#define	_SSL_get_sess_prkey(a)	_SSL_get_sess_obj(a, 1)
#define	_SSL_get_sess_x509(a)	_SSL_get_sess_obj(a, 2)
/*char *_SSL_get_obj_base64(void *s, int type);*/		/* must be freed */
#define	_SSL_get_pkey_base64(a)		_SSL_get_obj_base64(a, 0)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -52,7 +52,7 @@
     int SSL_get_fd(SSL *);
 */
 void _SSL_close (SSL * ssl);
-
+int _SSL_check_hostname(X509 *cert, const char *host);
 int _SSL_get_cert_info (struct cert_info *cert_info, SSL * ssl);
 struct chiper_info *_SSL_get_cipher_info (SSL * ssl);
 
```
