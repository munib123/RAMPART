# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 214_1
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `214_1`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 357-397 of the vulnerable file.

	to->di_dmstate = cpu_to_be16(from->di_dmstate);
	to->di_flags = cpu_to_be16(from->di_flags);
	to->di_gen = cpu_to_be32(from->di_gen);

	if (from->di_version == 3) {
		to->di_changecount = cpu_to_be64(from->di_changecount);
		to->di_crtime.t_sec = cpu_to_be32(from->di_crtime.t_sec);
		to->di_crtime.t_nsec = cpu_to_be32(from->di_crtime.t_nsec);
		to->di_flags2 = cpu_to_be64(from->di_flags2);
		to->di_cowextsize = cpu_to_be32(from->di_cowextsize);
		to->di_ino = cpu_to_be64(from->di_ino);
		to->di_lsn = cpu_to_be64(from->di_lsn);
		memcpy(to->di_pad2, from->di_pad2, sizeof(to->di_pad2));
		uuid_copy(&to->di_uuid, &from->di_uuid);
		to->di_flushiter = 0;
	} else {
		to->di_flushiter = cpu_to_be16(from->di_flushiter);
	}
}

xfs_failaddr_t
xfs_dinode_verify(
	struct xfs_mount	*mp,
	xfs_ino_t		ino,
	struct xfs_dinode	*dip)
{
	xfs_failaddr_t		fa;
	uint16_t		mode;
	uint16_t		flags;
	uint64_t		flags2;
	uint64_t		di_size;

	if (dip->di_magic != cpu_to_be16(XFS_DINODE_MAGIC))
		return __this_address;

	/* Verify v3 integrity information first */
	if (dip->di_version >= 3) {
		if (!xfs_sb_version_hascrc(&mp->m_sb))
			return __this_address;
		if (!xfs_verify_cksum((char *)dip, mp->m_sb.sb_inodesize,
				      XFS_DINODE_CRC_OFF))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -374,6 +374,47 @@
 	}
 }
 
+static xfs_failaddr_t
+xfs_dinode_verify_fork(
+	struct xfs_dinode	*dip,
+	struct xfs_mount	*mp,
+	int			whichfork)
+{
+	uint32_t		di_nextents = XFS_DFORK_NEXTENTS(dip, whichfork);
+
+	switch (XFS_DFORK_FORMAT(dip, whichfork)) {
+	case XFS_DINODE_FMT_LOCAL:
+		/*
+		 * no local regular files yet
+		 */
+		if (whichfork == XFS_DATA_FORK) {
+			if (S_ISREG(be16_to_cpu(dip->di_mode)))
+				return __this_address;
+			if (be64_to_cpu(dip->di_size) >
+					XFS_DFORK_SIZE(dip, mp, whichfork))
+				return __this_address;
+		}
+		if (di_nextents)
+			return __this_address;
+		break;
+	case XFS_DINODE_FMT_EXTENTS:
+		if (di_nextents > XFS_DFORK_MAXEXT(dip, mp, whichfork))
+			return __this_address;
+		break;
+	case XFS_DINODE_FMT_BTREE:
+		if (whichfork == XFS_ATTR_FORK) {
+			if (di_nextents > MAXAEXTNUM)
+				return __this_address;
+		} else if (di_nextents > MAXEXTNUM) {
+			return __this_address;
+		}
+		break;
+	default:
+		return __this_address;
+	}
+	return NULL;
+}
+
 xfs_failaddr_t
 xfs_dinode_verify(
 	struct xfs_mount	*mp,
@@ -441,24 +482,9 @@
 	case S_IFREG:
 	case S_IFLNK:
 	case S_IFDIR:
-		switch (dip->di_format) {
-		case XFS_DINODE_FMT_LOCAL:
-			/*
-			 * no local regular files yet
-			 */
-			if (S_ISREG(mode))
-				return __this_address;
-			if (di_size > XFS_DFORK_DSIZE(dip, mp))
-				return __this_address;
-			if (dip->di_nextents)
-				return __this_address;
-			/* fall through */
-		case XFS_DINODE_FMT_EXTENTS:
-		case XFS_DINODE_FMT_BTREE:
-			break;
-		default:
-			return __this_address;
-		}
+		fa = xfs_dinode_verify_fork(dip, mp, XFS_DATA_FORK);
+		if (fa)
+			return fa;
 		break;
 	case 0:
 		/* Uninitialized inode ok. */
@@ -468,17 +494,9 @@
 	}
 
 	if (XFS_DFORK_Q(dip)) {
-		switch (dip->di_aformat) {
-		case XFS_DINODE_FMT_LOCAL:
-			if (dip->di_anextents)
-				return __this_address;
-		/* fall through */
-		case XFS_DINODE_FMT_EXTENTS:
-		case XFS_DINODE_FMT_BTREE:
-			break;
-		default:
-			return __this_address;
-		}
+		fa = xfs_dinode_verify_fork(dip, mp, XFS_ATTR_FORK);
+		if (fa)
+			return fa;
 	} else {
 		/*
 		 * If there is no fork offset, this may be a freshly-made inode
```
