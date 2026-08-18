# CrossVul Fix Pair: Incorrect Permission Assignment for Critical Resource in c
**Pair ID:** 4284_6
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-732
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4284_6`)

## Vulnerability Information & PoC

## Description
Incorrect Permission Assignment for Critical Resource - When a resource is given a permission setting that provides access to a wider range of actors than required, it could lead to the exposure of sensitive information, or the modification of that reso...

## Vulnerable Code
```c
Lines 370-410 of the vulnerable file.


	if (zfsvfs->z_fuid_obj || zfsvfs->z_fuid_dirty)
		domain = zfs_fuid_idx_domain(&zfsvfs->z_fuid_idx, idx);
	else
		domain = nulldomain;
	rw_exit(&zfsvfs->z_fuid_lock);

	ASSERT(domain);
	return (domain);
}

void
zfs_fuid_map_ids(znode_t *zp, cred_t *cr, uid_t *uidp, uid_t *gidp)
{
	*uidp = zfs_fuid_map_id(ZTOZSB(zp), KUID_TO_SUID(ZTOUID(zp)),
	    cr, ZFS_OWNER);
	*gidp = zfs_fuid_map_id(ZTOZSB(zp), KGID_TO_SGID(ZTOGID(zp)),
	    cr, ZFS_GROUP);
}

uid_t
zfs_fuid_map_id(zfsvfs_t *zfsvfs, uint64_t fuid,
    cred_t *cr, zfs_fuid_type_t type)
{
#ifdef HAVE_KSID
	uint32_t index = FUID_INDEX(fuid);
	const char *domain;
	uid_t id;

	if (index == 0)
		return (fuid);

	domain = zfs_fuid_find_by_idx(zfsvfs, index);
	ASSERT(domain != NULL);

	if (type == ZFS_OWNER || type == ZFS_ACE_USER) {
		(void) kidmap_getuidbysid(crgetzone(cr), domain,
		    FUID_RID(fuid), &id);
	} else {
		(void) kidmap_getgidbysid(crgetzone(cr), domain,
		    FUID_RID(fuid), &id);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -387,11 +387,34 @@
 	    cr, ZFS_GROUP);
 }
 
+#ifdef __FreeBSD__
 uid_t
 zfs_fuid_map_id(zfsvfs_t *zfsvfs, uint64_t fuid,
     cred_t *cr, zfs_fuid_type_t type)
 {
-#ifdef HAVE_KSID
+	uint32_t index = FUID_INDEX(fuid);
+
+	if (index == 0)
+		return (fuid);
+
+	return (UID_NOBODY);
+}
+#elif defined(__linux__)
+uid_t
+zfs_fuid_map_id(zfsvfs_t *zfsvfs, uint64_t fuid,
+    cred_t *cr, zfs_fuid_type_t type)
+{
+	/*
+	 * The Linux port only supports POSIX IDs, use the passed id.
+	 */
+	return (fuid);
+}
+
+#else
+uid_t
+zfs_fuid_map_id(zfsvfs_t *zfsvfs, uint64_t fuid,
+    cred_t *cr, zfs_fuid_type_t type)
+{
 	uint32_t index = FUID_INDEX(fuid);
 	const char *domain;
 	uid_t id;
@@ -410,13 +433,8 @@
 		    FUID_RID(fuid), &id);
 	}
 	return (id);
-#else
-	/*
-	 * The Linux port only supports POSIX IDs, use the passed id.
-	 */
-	return (fuid);
-#endif /* HAVE_KSID */
-}
+}
+#endif
 
 /*
  * Add a FUID node to the list of fuid's being created for this
@@ -559,9 +577,9 @@
 	const char *domain;
 	char *kdomain;
 	uint32_t fuid_idx = FUID_INDEX(id);
-	uint32_t rid;
+	uint32_t rid = 0;
 	idmap_stat status;
-	uint64_t idx = 0;
+	uint64_t idx = UID_NOBODY;
 	zfs_fuid_t *zfuid = NULL;
 	zfs_fuid_info_t *fuidp = NULL;
 
@@ -711,9 +729,11 @@
 zfs_groupmember(zfsvfs_t *zfsvfs, uint64_t id, cred_t *cr)
 {
 #ifdef HAVE_KSID
+	uid_t		gid;
+
+#ifdef illumos
 	ksid_t		*ksid = crgetsid(cr, KSID_GROUP);
 	ksidlist_t	*ksidlist = crgetsidlist(cr);
-	uid_t		gid;
 
 	if (ksid && ksidlist) {
 		int		i;
@@ -746,6 +766,7 @@
 			}
 		}
 	}
+#endif /* illumos */
 
 	/*
 	 * Not found in ksidlist, check posix groups
```
