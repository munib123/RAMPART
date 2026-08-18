# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 2375_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2375_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 47-96 of the vulnerable file.


#ifdef DEBUG_GSSAPI
int svc_debug_gss = DEBUG_GSSAPI;
#endif

#ifdef SPKM

#ifndef OID_EQ
#define g_OID_equal(o1,o2) \
   (((o1)->length == (o2)->length) && \
    ((o1)->elements != 0) && ((o2)->elements != 0) && \
    (memcmp((o1)->elements,(o2)->elements,(int) (o1)->length) == 0))
#define OID_EQ 1
#endif /* OID_EQ */

extern const gss_OID_desc * const gss_mech_spkm3;

#endif /* SPKM */

extern SVCAUTH svc_auth_none;

/*
 * from mit-krb5-1.2.1 mechglue/mglueP.h:
 * Array of context IDs typed by mechanism OID
 */
typedef struct gss_union_ctx_id_t {
  gss_OID     mech_type;
  gss_ctx_id_t    internal_ctx_id;
} gss_union_ctx_id_desc, *gss_union_ctx_id_t;


static auth_gssapi_log_badauth_func log_badauth = NULL;
static caddr_t log_badauth_data = NULL;
static auth_gssapi_log_badauth2_func log_badauth2 = NULL;
static caddr_t log_badauth2_data = NULL;
static auth_gssapi_log_badverf_func log_badverf = NULL;
static caddr_t log_badverf_data = NULL;
static auth_gssapi_log_miscerr_func log_miscerr = NULL;
static caddr_t log_miscerr_data = NULL;

#define LOG_MISCERR(arg) if (log_miscerr) \
        (*log_miscerr)(rqst, msg, arg, log_miscerr_data)

static bool_t	svcauth_gss_destroy(SVCAUTH *);
static bool_t   svcauth_gss_wrap(SVCAUTH *, XDR *, xdrproc_t, caddr_t);
static bool_t   svcauth_gss_unwrap(SVCAUTH *, XDR *, xdrproc_t, caddr_t);

static bool_t	svcauth_gss_nextverf(struct svc_req *, u_int);

struct svc_auth_ops svc_auth_gss_ops = {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -64,16 +64,6 @@
 #endif /* SPKM */
 
 extern SVCAUTH svc_auth_none;
-
-/*
- * from mit-krb5-1.2.1 mechglue/mglueP.h:
- * Array of context IDs typed by mechanism OID
- */
-typedef struct gss_union_ctx_id_t {
-  gss_OID     mech_type;
-  gss_ctx_id_t    internal_ctx_id;
-} gss_union_ctx_id_desc, *gss_union_ctx_id_t;
-
 
 static auth_gssapi_log_badauth_func log_badauth = NULL;
 static caddr_t log_badauth_data = NULL;
@@ -239,16 +229,8 @@
 		gd->ctx = GSS_C_NO_CONTEXT;
 		goto errout;
 	}
-	/*
-	 * ANDROS: krb5 mechglue returns ctx of size 8 - two pointers,
-	 * one to the mechanism oid, one to the internal_ctx_id
-	 */
-	if ((gr->gr_ctx.value = mem_alloc(sizeof(gss_union_ctx_id_desc))) == NULL) {
-		fprintf(stderr, "svcauth_gss_accept_context: out of memory\n");
-		goto errout;
-	}
-	memcpy(gr->gr_ctx.value, gd->ctx, sizeof(gss_union_ctx_id_desc));
-	gr->gr_ctx.length = sizeof(gss_union_ctx_id_desc);
+	gr->gr_ctx.value = "xxxx";
+	gr->gr_ctx.length = 4;
 
 	/* gr->gr_win = 0x00000005; ANDROS: for debugging linux kernel version...  */
 	gr->gr_win = sizeof(gd->seqmask) * 8;
@@ -520,8 +502,6 @@
 
 		if (!svcauth_gss_nextverf(rqst, htonl(gr.gr_win))) {
 			gss_release_buffer(&min_stat, &gr.gr_token);
-			mem_free(gr.gr_ctx.value,
-				 sizeof(gss_union_ctx_id_desc));
 			ret_freegc (AUTH_FAILED);
 		}
 		*no_dispatch = TRUE;
@@ -531,7 +511,6 @@
 
 		gss_release_buffer(&min_stat, &gr.gr_token);
 		gss_release_buffer(&min_stat, &gd->checksum);
-		mem_free(gr.gr_ctx.value, sizeof(gss_union_ctx_id_desc));
 		if (!call_stat)
 			ret_freegc (AUTH_FAILED);
 
```
