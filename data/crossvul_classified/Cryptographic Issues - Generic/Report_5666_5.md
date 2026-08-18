# CrossVul Fix Pair: Cryptographic Issues in c
**Pair ID:** 5666_5
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5666_5`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```c
Lines 36-77 of the vulnerable file.

static int crypto_pcomp_init(struct crypto_tfm *tfm, u32 type, u32 mask)
{
	return 0;
}

static unsigned int crypto_pcomp_extsize(struct crypto_alg *alg)
{
	return alg->cra_ctxsize;
}

static int crypto_pcomp_init_tfm(struct crypto_tfm *tfm)
{
	return 0;
}

#ifdef CONFIG_NET
static int crypto_pcomp_report(struct sk_buff *skb, struct crypto_alg *alg)
{
	struct crypto_report_comp rpcomp;

	snprintf(rpcomp.type, CRYPTO_MAX_ALG_NAME, "%s", "pcomp");

	if (nla_put(skb, CRYPTOCFGA_REPORT_COMPRESS,
		    sizeof(struct crypto_report_comp), &rpcomp))
		goto nla_put_failure;
	return 0;

nla_put_failure:
	return -EMSGSIZE;
}
#else
static int crypto_pcomp_report(struct sk_buff *skb, struct crypto_alg *alg)
{
	return -ENOSYS;
}
#endif

static void crypto_pcomp_show(struct seq_file *m, struct crypto_alg *alg)
	__attribute__ ((unused));
static void crypto_pcomp_show(struct seq_file *m, struct crypto_alg *alg)
{
	seq_printf(m, "type         : pcomp\n");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -53,8 +53,7 @@
 {
 	struct crypto_report_comp rpcomp;
 
-	snprintf(rpcomp.type, CRYPTO_MAX_ALG_NAME, "%s", "pcomp");
-
+	strncpy(rpcomp.type, "pcomp", sizeof(rpcomp.type));
 	if (nla_put(skb, CRYPTOCFGA_REPORT_COMPRESS,
 		    sizeof(struct crypto_report_comp), &rpcomp))
 		goto nla_put_failure;
```
