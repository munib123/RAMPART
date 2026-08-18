# CrossVul Fix Pair: DEPRECATED: Source Code in c
**Pair ID:** 1534_0
**Vulnerability Class:** DEPRECATED- Source Code
**CWE:** CWE-18
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1534_0`)

## Vulnerability Information & PoC

## Description
DEPRECATED: Source Code

## Vulnerable Code
```c
Lines 86-126 of the vulnerable file.

	gss_cred_id_t mcred;	/* mechglue union of obtainable creds */
	gss_OID_set neg_mechs;	/* app-specified list of allowable mechs */
	int no_ask_integ;	/* do not request integ from mechs */
} spnego_gss_cred_id_rec, *spnego_gss_cred_id_t;

/* Structure for context handle */
typedef struct {
	OM_uint32	magic_num;
	gss_buffer_desc DER_mechTypes;
	gss_OID_set mech_set;
	gss_OID internal_mech;  /* alias into mech_set->elements */
	gss_ctx_id_t ctx_handle;
	char  *optionStr;
	gss_cred_id_t default_cred;
	int mic_reqd;
	int mic_sent;
	int mic_rcvd;
	int firstpass;
	int mech_complete;
	int nego_done;
	OM_uint32 ctx_flags;
	gss_name_t internal_name;
	gss_OID actual_mech;
} spnego_gss_ctx_id_rec, *spnego_gss_ctx_id_t;

/*
 * The magic number must be less than a standard pagesize
 * to avoid a possible collision with a real address.
 */
#define	SPNEGO_MAGIC_ID  0x00000fed

/* SPNEGO oid declarations */
extern const gss_OID_desc * const gss_mech_spnego;
extern const gss_OID_set_desc * const gss_mech_set_spnego;

#if defined(DEBUG) && defined(HAVE_SYSLOG_H)
#include <syslog.h>
#define	dsyslog(a) syslog(LOG_DEBUG, a)
#else
#define	dsyslog(a)
#define	SPNEGO_STATIC
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -103,6 +103,8 @@
 	int firstpass;
 	int mech_complete;
 	int nego_done;
+	int initiate;
+	int opened;
 	OM_uint32 ctx_flags;
 	gss_name_t internal_name;
 	gss_OID actual_mech;
```
