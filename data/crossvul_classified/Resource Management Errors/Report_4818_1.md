# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 4818_1
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4818_1`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 26-53 of the vulnerable file.

			  const struct ceph_crypto_key *src);
int ceph_crypto_key_encode(struct ceph_crypto_key *key, void **p, void *end);
int ceph_crypto_key_decode(struct ceph_crypto_key *key, void **p, void *end);
int ceph_crypto_key_unarmor(struct ceph_crypto_key *key, const char *in);

/* crypto.c */
int ceph_decrypt(struct ceph_crypto_key *secret,
		 void *dst, size_t *dst_len,
		 const void *src, size_t src_len);
int ceph_encrypt(struct ceph_crypto_key *secret,
		 void *dst, size_t *dst_len,
		 const void *src, size_t src_len);
int ceph_decrypt2(struct ceph_crypto_key *secret,
		  void *dst1, size_t *dst1_len,
		  void *dst2, size_t *dst2_len,
		  const void *src, size_t src_len);
int ceph_encrypt2(struct ceph_crypto_key *secret,
		  void *dst, size_t *dst_len,
		  const void *src1, size_t src1_len,
		  const void *src2, size_t src2_len);
int ceph_crypto_init(void);
void ceph_crypto_shutdown(void);

/* armor.c */
int ceph_armor(char *dst, const char *src, const char *end);
int ceph_unarmor(char *dst, const char *src, const char *end);

#endif
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -43,6 +43,8 @@
 		  void *dst, size_t *dst_len,
 		  const void *src1, size_t src1_len,
 		  const void *src2, size_t src2_len);
+int ceph_crypt(const struct ceph_crypto_key *key, bool encrypt,
+	       void *buf, int buf_len, int in_len, int *pout_len);
 int ceph_crypto_init(void);
 void ceph_crypto_shutdown(void);
 
```
