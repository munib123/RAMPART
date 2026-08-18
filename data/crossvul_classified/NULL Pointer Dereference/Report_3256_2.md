# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 3256_2
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3256_2`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 50-90 of the vulnerable file.

} __packed;

#define FS_ENCRYPTION_CONTEXT_FORMAT_V1		1

/* This is passed in from userspace into the kernel keyring */
struct fscrypt_key {
	u32 mode;
	u8 raw[FS_MAX_KEY_SIZE];
	u32 size;
} __packed;

/*
 * A pointer to this structure is stored in the file system's in-core
 * representation of an inode.
 */
struct fscrypt_info {
	u8 ci_data_mode;
	u8 ci_filename_mode;
	u8 ci_flags;
	struct crypto_skcipher *ci_ctfm;
	struct key *ci_keyring_key;
	u8 ci_master_key[FS_KEY_DESCRIPTOR_SIZE];
};

typedef enum {
	FS_DECRYPT = 0,
	FS_ENCRYPT,
} fscrypt_direction_t;

#define FS_CTX_REQUIRES_FREE_ENCRYPT_FL		0x00000001
#define FS_CTX_HAS_BOUNCE_BUFFER_FL		0x00000002

struct fscrypt_completion_result {
	struct completion completion;
	int res;
};

#define DECLARE_FS_COMPLETION_RESULT(ecr) \
	struct fscrypt_completion_result ecr = { \
		COMPLETION_INITIALIZER_ONSTACK((ecr).completion), 0 }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -67,7 +67,6 @@
 	u8 ci_filename_mode;
 	u8 ci_flags;
 	struct crypto_skcipher *ci_ctfm;
-	struct key *ci_keyring_key;
 	u8 ci_master_key[FS_KEY_DESCRIPTOR_SIZE];
 };
 
@@ -101,7 +100,4 @@
 extern struct page *fscrypt_alloc_bounce_page(struct fscrypt_ctx *ctx,
 					      gfp_t gfp_flags);
 
-/* keyinfo.c */
-extern int fscrypt_get_crypt_info(struct inode *);
-
 #endif /* _FSCRYPT_PRIVATE_H */
```
