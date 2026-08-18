# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2899_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2899_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 688-728 of the vulnerable file.

			}
		}
	}
beach:
	free (data);
	return sdb;
}

static Sdb *store_versioninfo_gnu_verdef(ELFOBJ *bin, Elf_(Shdr) *shdr, int sz) {
	const char *section_name = "";
	const char *link_section_name = "";
	char *end = NULL;
	Elf_(Shdr) *link_shdr = NULL;
	ut8 dfs[sizeof (Elf_(Verdef))] = {0};
	Sdb *sdb;
	int cnt, i;
	if (shdr->sh_link > bin->ehdr.e_shnum) {
		return false;
	}
	link_shdr = &bin->shdr[shdr->sh_link];
	if (shdr->sh_size < 1) {
		return false;
	}
	Elf_(Verdef) *defs = calloc (shdr->sh_size, sizeof (char));
	if (!defs) {
		return false;
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
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -705,7 +705,7 @@
 		return false;
 	}
 	link_shdr = &bin->shdr[shdr->sh_link];
-	if (shdr->sh_size < 1) {
+	if (shdr->sh_size < 1 || shdr->sh_size > SIZE_MAX) {
 		return false;
 	}
 	Elf_(Verdef) *defs = calloc (shdr->sh_size, sizeof (char));
@@ -837,7 +837,7 @@
 	if (shdr->sh_link > bin->ehdr.e_shnum) {
 		return NULL;
 	}
-	if (shdr->sh_size < 1) {
+	if (shdr->sh_size < 1 || shdr->sh_size > SIZE_MAX) {
 		return NULL;
 	}
 	sdb = sdb_new0 ();
```
