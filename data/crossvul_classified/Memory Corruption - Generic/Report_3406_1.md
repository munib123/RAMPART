# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3406_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3406_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 378-418 of the vulnerable file.

				if (mode == R_CORE_BIN_RADARE || mode == R_CORE_BIN_JSON || mode == R_CORE_BIN_SIMPLE) {
					RBININFO ("sections", R_CORE_BIN_ACC_SECTIONS, input + 2,
						obj? r_list_length (obj->sections): 0);
				} else {
					RBININFO ("sections", R_CORE_BIN_ACC_SECTIONS, input + 1,
						obj? r_list_length (obj->sections): 0);
				}
				//we move input until get '\0'
				while (*(++input)) ;
				//input-- because we are inside a while that does input++
				// oob read if not input--
				input--;
			}
			break;
		case 'H':
			if (input[1] == 'H') { // "iHH"
				RBININFO ("header", R_CORE_BIN_ACC_HEADER, NULL, -1);
				break;
			}
		case 'h': RBININFO ("fields", R_CORE_BIN_ACC_FIELDS, NULL, 0); break;
		case 'l': RBININFO ("libs", R_CORE_BIN_ACC_LIBS, NULL, obj? r_list_length (obj->libs): 0); break;
		case 'L':
		{
			char *ptr = strchr (input, ' ');
			int json = input[1] == 'j'? 'j': 0;

			if (ptr && ptr[1]) {
				const char *plugin_name = ptr + 1;
				if (is_array) {
					r_cons_printf ("\"plugin\": ");
				}
				r_bin_list_plugin (core->bin, plugin_name, json);
			} else {
				r_bin_list (core->bin, json);
			}

			newline = false;

			goto done;
		}
		break;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -395,7 +395,12 @@
 				break;
 			}
 		case 'h': RBININFO ("fields", R_CORE_BIN_ACC_FIELDS, NULL, 0); break;
-		case 'l': RBININFO ("libs", R_CORE_BIN_ACC_LIBS, NULL, obj? r_list_length (obj->libs): 0); break;
+		case 'l': 
+			  {
+				  RBinObject *obj = r_bin_cur_object (core->bin);
+				  RBININFO ("libs", R_CORE_BIN_ACC_LIBS, NULL, obj? r_list_length (obj->libs): 0); 
+			  }
+			  break;
 		case 'L':
 		{
 			char *ptr = strchr (input, ' ');
@@ -444,7 +449,12 @@
 			break;
 		case 'r': RBININFO ("relocs", R_CORE_BIN_ACC_RELOCS, NULL, 0); break;
 		case 'd': RBININFO ("dwarf", R_CORE_BIN_ACC_DWARF, NULL, -1); break;
-		case 'i': RBININFO ("imports",R_CORE_BIN_ACC_IMPORTS, NULL, obj? r_list_length (obj->imports): 0); break;
+		case 'i': {
+				  RBinObject *obj = r_bin_cur_object (core->bin);
+				  RBININFO ("imports", R_CORE_BIN_ACC_IMPORTS, NULL,
+						  obj? r_list_length (obj->imports): 0);
+			  }
+			  break;
 		case 'I': RBININFO ("info", R_CORE_BIN_ACC_INFO, NULL, 0); break;
 		case 'e': RBININFO ("entries", R_CORE_BIN_ACC_ENTRIES, NULL, 0); break;
 		case 'M': RBININFO ("main", R_CORE_BIN_ACC_MAIN, NULL, 0); break;
```
