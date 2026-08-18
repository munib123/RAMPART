# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2889_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2889_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 883-923 of the vulnerable file.

			goto beach;
		}
		j = 0;
		vvn.vn_version = READ16 (vstart, j)
		vvn.vn_cnt = READ16 (vstart, j)
		vvn.vn_file = READ32 (vstart, j)
		vvn.vn_aux = READ32 (vstart, j)
		vvn.vn_next = READ32 (vstart, j)

		sdb_num_set (sdb_version, "vn_version", entry->vn_version, 0);
		sdb_num_set (sdb_version, "idx", i, 0);
		if (entry->vn_file > bin->dynstr_size) {
			goto beach;
		}
		{
			char *s = r_str_ndup (&bin->dynstr[entry->vn_file], 16);
			sdb_set (sdb_version, "file_name", s, 0);
			free (s);
		}
		sdb_num_set (sdb_version, "cnt", entry->vn_cnt, 0);
		vstart += entry->vn_aux;
		for (j = 0, isum = i + entry->vn_aux; j < entry->vn_cnt && vstart + sizeof (Elf_(Vernaux)) <= end; ++j) {
			int k;
			Elf_(Vernaux) * aux = NULL;
			Elf_(Vernaux) vaux = {0};
			sdb_vernaux = sdb_new0 ();
			if (!sdb_vernaux) {
				goto beach;
			}
			aux = (Elf_(Vernaux)*)&vaux;
			k = 0;
			vaux.vna_hash = READ32 (vstart, k)
			vaux.vna_flags = READ16 (vstart, k)
			vaux.vna_other = READ16 (vstart, k)
			vaux.vna_name = READ32 (vstart, k)
			vaux.vna_next = READ32 (vstart, k)
			if (aux->vna_name > bin->dynstr_size) {
				goto beach;
			}
			sdb_num_set (sdb_vernaux, "idx", isum, 0);
			if (aux->vna_name > 0 && aux->vna_name + 8 < bin->dynstr_size) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -900,7 +900,11 @@
 			free (s);
 		}
 		sdb_num_set (sdb_version, "cnt", entry->vn_cnt, 0);
-		vstart += entry->vn_aux;
+		st32 vnaux = entry->vn_aux;
+		if (vnaux < 1) {
+			goto beach;
+		}
+		vstart += vnaux;
 		for (j = 0, isum = i + entry->vn_aux; j < entry->vn_cnt && vstart + sizeof (Elf_(Vernaux)) <= end; ++j) {
 			int k;
 			Elf_(Vernaux) * aux = NULL;
```
