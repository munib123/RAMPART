# CrossVul Fix Pair: Improper Resource Shutdown or Release in c
**Pair ID:** 3351_5
**Vulnerability Class:** Improper Resource Shutdown or Release
**CWE:** CWE-404
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3351_5`)

## Vulnerability Information & PoC

## Description
Improper Resource Shutdown or Release - When a resource is created or allocated, the developer is responsible for properly releasing the resource as well as accounting for all potential paths of expiration or invalidation, such as a set ...

## Vulnerable Code
```c
Lines 1895-1945 of the vulnerable file.


static void expire_client(struct nfs4_client *clp)
{
	unhash_client(clp);
	nfsd4_client_record_remove(clp);
	__destroy_client(clp);
}

static void copy_verf(struct nfs4_client *target, nfs4_verifier *source)
{
	memcpy(target->cl_verifier.data, source->data,
			sizeof(target->cl_verifier.data));
}

static void copy_clid(struct nfs4_client *target, struct nfs4_client *source)
{
	target->cl_clientid.cl_boot = source->cl_clientid.cl_boot; 
	target->cl_clientid.cl_id = source->cl_clientid.cl_id; 
}

int strdup_if_nonnull(char **target, char *source)
{
	if (source) {
		*target = kstrdup(source, GFP_KERNEL);
		if (!*target)
			return -ENOMEM;
	} else
		*target = NULL;
	return 0;
}

static int copy_cred(struct svc_cred *target, struct svc_cred *source)
{
	int ret;

	ret = strdup_if_nonnull(&target->cr_principal, source->cr_principal);
	if (ret)
		return ret;
	ret = strdup_if_nonnull(&target->cr_raw_principal,
					source->cr_raw_principal);
	if (ret)
		return ret;
	target->cr_flavor = source->cr_flavor;
	target->cr_uid = source->cr_uid;
	target->cr_gid = source->cr_gid;
	target->cr_group_info = source->cr_group_info;
	get_group_info(target->cr_group_info);
	target->cr_gss_mech = source->cr_gss_mech;
	if (source->cr_gss_mech)
		gss_mech_get(source->cr_gss_mech);
	return 0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1912,28 +1912,15 @@
 	target->cl_clientid.cl_id = source->cl_clientid.cl_id; 
 }
 
-int strdup_if_nonnull(char **target, char *source)
-{
-	if (source) {
-		*target = kstrdup(source, GFP_KERNEL);
-		if (!*target)
-			return -ENOMEM;
-	} else
-		*target = NULL;
-	return 0;
-}
-
 static int copy_cred(struct svc_cred *target, struct svc_cred *source)
 {
-	int ret;
-
-	ret = strdup_if_nonnull(&target->cr_principal, source->cr_principal);
-	if (ret)
-		return ret;
-	ret = strdup_if_nonnull(&target->cr_raw_principal,
-					source->cr_raw_principal);
-	if (ret)
-		return ret;
+	target->cr_principal = kstrdup(source->cr_principal, GFP_KERNEL);
+	target->cr_raw_principal = kstrdup(source->cr_raw_principal,
+								GFP_KERNEL);
+	if ((source->cr_principal && ! target->cr_principal) ||
+	    (source->cr_raw_principal && ! target->cr_raw_principal))
+		return -ENOMEM;
+
 	target->cr_flavor = source->cr_flavor;
 	target->cr_uid = source->cr_uid;
 	target->cr_gid = source->cr_gid;
```
