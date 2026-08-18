# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 3527_2
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3527_2`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 585-625 of the vulnerable file.

	struct nfs4_sequence_args 	seq_args;
};

struct nfs_setaclargs {
	struct nfs_fh *			fh;
	size_t				acl_len;
	unsigned int			acl_pgbase;
	struct page **			acl_pages;
	struct nfs4_sequence_args	seq_args;
};

struct nfs_setaclres {
	struct nfs4_sequence_res	seq_res;
};

struct nfs_getaclargs {
	struct nfs_fh *			fh;
	size_t				acl_len;
	unsigned int			acl_pgbase;
	struct page **			acl_pages;
	struct nfs4_sequence_args 	seq_args;
};

struct nfs_getaclres {
	size_t				acl_len;
	struct nfs4_sequence_res	seq_res;
};

struct nfs_setattrres {
	struct nfs_fattr *              fattr;
	const struct nfs_server *	server;
	struct nfs4_sequence_res	seq_res;
};

struct nfs_linkargs {
	struct nfs_fh *		fromfh;
	struct nfs_fh *		tofh;
	const char *		toname;
	unsigned int		tolen;
};

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -602,11 +602,16 @@
 	size_t				acl_len;
 	unsigned int			acl_pgbase;
 	struct page **			acl_pages;
+	struct page *			acl_scratch;
 	struct nfs4_sequence_args 	seq_args;
 };
 
+/* getxattr ACL interface flags */
+#define NFS4_ACL_LEN_REQUEST	0x0001	/* zero length getxattr buffer */
 struct nfs_getaclres {
 	size_t				acl_len;
+	size_t				acl_data_offset;
+	int				acl_flags;
 	struct nfs4_sequence_res	seq_res;
 };
 
```
