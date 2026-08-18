# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 2902_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2902_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 732-772 of the vulnerable file.

	sdb_set (sdb, "link_section_name", link_section_name, 0);

	for (cnt = 0, i = 0; i >= 0 && cnt < shdr->sh_info && (end - (char *)defs > i); ++cnt) {
		Sdb *sdb_verdef = sdb_new0 ();
		char *vstart = ((char*)defs) + i;
		char key[32] = {0};
		Elf_(Verdef) *verdef = (Elf_(Verdef)*)vstart;
		Elf_(Verdaux) aux = {0};
		int j = 0;
		int isum = 0;

		r_buf_read_at (bin->b, shdr->sh_offset + i, dfs, sizeof (Elf_(Verdef)));
		verdef->vd_version = READ16 (dfs, j)
		verdef->vd_flags = READ16 (dfs, j)
		verdef->vd_ndx = READ16 (dfs, j)
		verdef->vd_cnt = READ16 (dfs, j)
		verdef->vd_hash = READ32 (dfs, j)
		verdef->vd_aux = READ32 (dfs, j)
		verdef->vd_next = READ32 (dfs, j)
		int vdaux = verdef->vd_aux;
		if (vdaux < 1 || (char *)UINTPTR_MAX - vstart < vdaux) {
			sdb_free (sdb_verdef);
			goto out_error;
		}
		vstart += vdaux;
		if (vstart > end || end - vstart < sizeof (Elf_(Verdaux))) {
			sdb_free (sdb_verdef);
			goto out_error;
		}

		j = 0;
		aux.vda_name = READ32 (vstart, j)
		aux.vda_next = READ32 (vstart, j)

		isum = i + verdef->vd_aux;
		if (aux.vda_name > bin->dynstr_size) {
			sdb_free (sdb_verdef);
			goto out_error;
		}

		sdb_num_set (sdb_verdef, "idx", i, 0);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -749,7 +749,7 @@
 		verdef->vd_aux = READ32 (dfs, j)
 		verdef->vd_next = READ32 (dfs, j)
 		int vdaux = verdef->vd_aux;
-		if (vdaux < 1 || (char *)UINTPTR_MAX - vstart < vdaux) {
+		if (vdaux < 1 || vstart + vdaux < vstart) {
 			sdb_free (sdb_verdef);
 			goto out_error;
 		}
```
