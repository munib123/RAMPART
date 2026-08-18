# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5603_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5603_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 5636-5676 of the vulnerable file.

	return 0;
}

/*
 * SCTP_GET_ASSOC_STATS
 *
 * This option retrieves local per endpoint statistics. It is modeled
 * after OpenSolaris' implementation
 */
static int sctp_getsockopt_assoc_stats(struct sock *sk, int len,
				       char __user *optval,
				       int __user *optlen)
{
	struct sctp_assoc_stats sas;
	struct sctp_association *asoc = NULL;

	/* User must provide at least the assoc id */
	if (len < sizeof(sctp_assoc_t))
		return -EINVAL;

	if (copy_from_user(&sas, optval, len))
		return -EFAULT;

	asoc = sctp_id2assoc(sk, sas.sas_assoc_id);
	if (!asoc)
		return -EINVAL;

	sas.sas_rtxchunks = asoc->stats.rtxchunks;
	sas.sas_gapcnt = asoc->stats.gapcnt;
	sas.sas_outofseqtsns = asoc->stats.outofseqtsns;
	sas.sas_osacks = asoc->stats.osacks;
	sas.sas_isacks = asoc->stats.isacks;
	sas.sas_octrlchunks = asoc->stats.octrlchunks;
	sas.sas_ictrlchunks = asoc->stats.ictrlchunks;
	sas.sas_oodchunks = asoc->stats.oodchunks;
	sas.sas_iodchunks = asoc->stats.iodchunks;
	sas.sas_ouodchunks = asoc->stats.ouodchunks;
	sas.sas_iuodchunks = asoc->stats.iuodchunks;
	sas.sas_idupchunks = asoc->stats.idupchunks;
	sas.sas_opackets = asoc->stats.opackets;
	sas.sas_ipackets = asoc->stats.ipackets;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5653,6 +5653,9 @@
 	if (len < sizeof(sctp_assoc_t))
 		return -EINVAL;
 
+	/* Allow the struct to grow and fill in as much as possible */
+	len = min_t(size_t, len, sizeof(sas));
+
 	if (copy_from_user(&sas, optval, len))
 		return -EFAULT;
 
@@ -5685,9 +5688,6 @@
 
 	/* Mark beginning of a new observation period */
 	asoc->stats.max_obs_rto = asoc->rto_min;
-
-	/* Allow the struct to grow and fill in as much as possible */
-	len = min_t(size_t, len, sizeof(sas));
 
 	if (put_user(len, optlen))
 		return -EFAULT;
```
