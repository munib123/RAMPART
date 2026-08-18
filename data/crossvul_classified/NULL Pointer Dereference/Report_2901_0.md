# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 2901_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2901_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 714-754 of the vulnerable file.

	}
	if (bin->shstrtab && shdr->sh_name < bin->shstrtab_size) {
		section_name = &bin->shstrtab[shdr->sh_name];
	}
	if (link_shdr && bin->shstrtab && link_shdr->sh_name < bin->shstrtab_size) {
		link_section_name = &bin->shstrtab[link_shdr->sh_name];
	}
	if (!defs) {
		bprintf ("Warning: Cannot allocate memory (Check Elf_(Verdef))\n");
		return NULL;
	}
	sdb = sdb_new0 ();
	end = (char *)defs + shdr->sh_size;
	sdb_set (sdb, "section_name", section_name, 0);
	sdb_num_set (sdb, "entries", shdr->sh_info, 0);
	sdb_num_set (sdb, "addr", shdr->sh_addr, 0);
	sdb_num_set (sdb, "offset", shdr->sh_offset, 0);
	sdb_num_set (sdb, "link", shdr->sh_link, 0);
	sdb_set (sdb, "link_section_name", link_section_name, 0);

	for (cnt = 0, i = 0; i >= 0 && cnt < shdr->sh_info && ((char *)defs + i < end); ++cnt) {
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
		if (vdaux < 1) {
			sdb_free (sdb_verdef);
			goto out_error;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -731,7 +731,7 @@
 	sdb_num_set (sdb, "link", shdr->sh_link, 0);
 	sdb_set (sdb, "link_section_name", link_section_name, 0);
 
-	for (cnt = 0, i = 0; i >= 0 && cnt < shdr->sh_info && ((char *)defs + i < end); ++cnt) {
+	for (cnt = 0, i = 0; i >= 0 && cnt < shdr->sh_info && (end - (char *)defs > i); ++cnt) {
 		Sdb *sdb_verdef = sdb_new0 ();
 		char *vstart = ((char*)defs) + i;
 		char key[32] = {0};
@@ -749,12 +749,12 @@
 		verdef->vd_aux = READ32 (dfs, j)
 		verdef->vd_next = READ32 (dfs, j)
 		int vdaux = verdef->vd_aux;
-		if (vdaux < 1) {
+		if (vdaux < 1 || (char *)UINTPTR_MAX - vstart < vdaux) {
 			sdb_free (sdb_verdef);
 			goto out_error;
 		}
 		vstart += vdaux;
-		if (vstart > end || vstart + sizeof (Elf_(Verdaux)) > end) {
+		if (vstart > end || end - vstart < sizeof (Elf_(Verdaux))) {
 			sdb_free (sdb_verdef);
 			goto out_error;
 		}
@@ -781,7 +781,7 @@
 			Sdb *sdb_parent = sdb_new0 ();
 			isum += aux.vda_next;
 			vstart += aux.vda_next;
-			if (vstart > end || vstart + sizeof(Elf_(Verdaux)) > end) {
+			if (vstart > end || end - vstart < sizeof (Elf_(Verdaux))) {
 				sdb_free (sdb_verdef);
 				sdb_free (sdb_parent);
 				goto out_error;
```
