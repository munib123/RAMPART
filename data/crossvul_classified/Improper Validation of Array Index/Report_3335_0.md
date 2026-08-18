# CrossVul Fix Pair: Improper Validation of Array Index in c
**Pair ID:** 3335_0
**Vulnerability Class:** Improper Validation of Array Index
**CWE:** CWE-129
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3335_0`)

## Vulnerability Information & PoC

## Description
Improper Validation of Array Index - The product uses untrusted input when calculating or using an array index, but the product does not validate or incorrectly validates the index to ensure the index references a valid position withi...

## Vulnerable Code
```c
Lines 1242-1282 of the vulnerable file.


static __be32
nfsd4_verify(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,
	     struct nfsd4_verify *verify)
{
	__be32 status;

	status = _nfsd4_verify(rqstp, cstate, verify);
	return status == nfserr_same ? nfs_ok : status;
}

#ifdef CONFIG_NFSD_PNFS
static const struct nfsd4_layout_ops *
nfsd4_layout_verify(struct svc_export *exp, unsigned int layout_type)
{
	if (!exp->ex_layout_types) {
		dprintk("%s: export does not support pNFS\n", __func__);
		return NULL;
	}

	if (!(exp->ex_layout_types & (1 << layout_type))) {
		dprintk("%s: layout type %d not supported\n",
			__func__, layout_type);
		return NULL;
	}

	return nfsd4_layout_ops[layout_type];
}

static __be32
nfsd4_getdeviceinfo(struct svc_rqst *rqstp,
		struct nfsd4_compound_state *cstate,
		struct nfsd4_getdeviceinfo *gdp)
{
	const struct nfsd4_layout_ops *ops;
	struct nfsd4_deviceid_map *map;
	struct svc_export *exp;
	__be32 nfserr;

	dprintk("%s: layout_type %u dev_id [0x%llx:0x%x] maxcnt %u\n",
	       __func__,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1259,7 +1259,8 @@
 		return NULL;
 	}
 
-	if (!(exp->ex_layout_types & (1 << layout_type))) {
+	if (layout_type >= LAYOUT_TYPE_MAX ||
+	    !(exp->ex_layout_types & (1 << layout_type))) {
 		dprintk("%s: layout type %d not supported\n",
 			__func__, layout_type);
 		return NULL;
```
