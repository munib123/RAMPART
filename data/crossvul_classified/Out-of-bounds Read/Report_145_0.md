# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 145_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `145_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1569-1609 of the vulnerable file.

						symbols[j].name[R_BIN_MACH0_STRING_LENGTH - 2] = 0;
					}
					free (symstr_dup);
				} else {
					symbols[j].name[0] = 0;
				}
				symbols[j].last = 0;
			}
			if (inSymtab (hash, symbols, symbols[j].name, symbols[j].addr)) {
				symbols[j].name[0] = 0;
				j--;
			}
		}
	}
	to = R_MIN (bin->nsymtab, bin->dysymtab.iundefsym + bin->dysymtab.nundefsym);
	for (i = bin->dysymtab.iundefsym; i < to; i++) {
		if (j > symbols_count) {
			bprintf ("mach0-get-symbols: error\n");
			break;
		}
		if (parse_import_stub(bin, &symbols[j], i))
			symbols[j++].last = 0;
	}

#if 1
// symtab is wrongly parsed and produces dupped syms with incorrect vaddr */
	for (i = 0; i < bin->nsymtab; i++) {
		struct MACH0_(nlist) *st = &bin->symtab[i];
#if 0
		bprintf ("stridx %d -> section %d type %d value = %d\n",
			st->n_strx, st->n_sect, st->n_type, st->n_value);
#endif
		stridx = st->n_strx;
		if (stridx >= 0 && stridx < bin->symstrlen) {
			symstr = (char*)bin->symstr + stridx;
		} else {
			symstr = "???";
		}
		// 0 is for imports
		// 1 is for symbols
		// 2 is for func.eh (exception handlers?)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1586,8 +1586,9 @@
 			bprintf ("mach0-get-symbols: error\n");
 			break;
 		}
-		if (parse_import_stub(bin, &symbols[j], i))
+		if (parse_import_stub(bin, &symbols[j], i)) {
 			symbols[j++].last = 0;
+		}
 	}
 
 #if 1
@@ -1662,12 +1663,16 @@
 
 	for (i = 0; i < bin->nsects; i++) {
 		if ((bin->sects[i].flags & SECTION_TYPE) == stype) {
-			for (j=0, sym=-1; bin->sects[i].reserved1+j < bin->nindirectsyms; j++)
-				if (idx == bin->indirectsyms[bin->sects[i].reserved1 + j]) {
+			for (j = 0, sym = -1; bin->sects[i].reserved1 + j < bin->nindirectsyms; j++) {
+				int indidx = bin->sects[i].reserved1 + j;
+				if (indidx < 0 || indidx >= bin->nindirectsyms) {
+					break;
+				}
+				if (idx == bin->indirectsyms[indidx]) {
 					sym = j;
 					break;
 				}
-
+			}
 			reloc->offset = sym == -1 ? 0 : bin->sects[i].offset + sym * wordsize;
 			reloc->addr = sym == -1 ? 0 : bin->sects[i].addr + sym * wordsize;
 			return true;
@@ -1681,8 +1686,9 @@
 	int i, j, idx, stridx;
 	const char *symstr;
 
-	if (!bin->symtab || !bin->symstr || !bin->sects || !bin->indirectsyms)
+	if (!bin->symtab || !bin->symstr || !bin->sects || !bin->indirectsyms) {
 		return NULL;
+	}
 	if (bin->dysymtab.nundefsym < 1 || bin->dysymtab.nundefsym > 0xfffff) {
 		return NULL;
 	}
```
