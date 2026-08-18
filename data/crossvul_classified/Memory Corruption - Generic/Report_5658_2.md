# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5658_2
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5658_2`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 57-87 of the vulnerable file.

	#define	RAD_MICROSOFT_MS_RAS_VERSION			18
	#define	RAD_MICROSOFT_MS_OLD_ARAP_PASSWORD		19
	#define	RAD_MICROSOFT_MS_NEW_ARAP_PASSWORD		20
	#define	RAD_MICROSOFT_MS_ARAP_PASSWORD_CHANGE_REASON	21
	#define	RAD_MICROSOFT_MS_FILTER				22
	#define	RAD_MICROSOFT_MS_ACCT_AUTH_TYPE			23
	#define	RAD_MICROSOFT_MS_ACCT_EAP_TYPE			24
	#define	RAD_MICROSOFT_MS_CHAP2_RESPONSE			25
	#define	RAD_MICROSOFT_MS_CHAP2_SUCCESS			26
	#define	RAD_MICROSOFT_MS_CHAP2_PW			27
	#define	RAD_MICROSOFT_MS_PRIMARY_DNS_SERVER		28
	#define	RAD_MICROSOFT_MS_SECONDARY_DNS_SERVER		29
	#define	RAD_MICROSOFT_MS_PRIMARY_NBNS_SERVER		30
	#define	RAD_MICROSOFT_MS_SECONDARY_NBNS_SERVER		31
	#define	RAD_MICROSOFT_MS_ARAP_CHALLENGE			33

#define SALT_LEN    2

struct rad_handle;

int	rad_get_vendor_attr(u_int32_t *, const void **, size_t *);
int	rad_put_vendor_addr(struct rad_handle *, int, int, struct in_addr);
int	rad_put_vendor_attr(struct rad_handle *, int, int, const void *,
	    size_t);
int	rad_put_vendor_int(struct rad_handle *, int, int, u_int32_t);
int	rad_put_vendor_string(struct rad_handle *, int, int, const char *);
int	rad_demangle_mppe_key(struct rad_handle *, const void *, size_t, u_char *, size_t *);

#endif /* _RADLIB_VS_H_ */

/* vim: set ts=8 sw=8 noet: */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -74,7 +74,7 @@
 
 struct rad_handle;
 
-int	rad_get_vendor_attr(u_int32_t *, const void **, size_t *);
+int	rad_get_vendor_attr(u_int32_t *, unsigned char *, const void **, size_t *, const void *, size_t);
 int	rad_put_vendor_addr(struct rad_handle *, int, int, struct in_addr);
 int	rad_put_vendor_attr(struct rad_handle *, int, int, const void *,
 	    size_t);
```
