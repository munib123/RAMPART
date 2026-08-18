# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 1363_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1363_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 4606-4646 of the vulnerable file.


    break;

  case 180:

    { (yyval.backup_token).token = actual_type;
                   (yyval.backup_token).actual = actual;
                 }

    break;

  case 181:

    {struct lys_restr *pattern = actual;
                                                                        actual = NULL;
#ifdef LY_ENABLED_CACHE
                                                                        if ((yyvsp[-2].backup_token).token != EXTENSION_INSTANCE &&
                                                                            !(data_node && data_node->nodetype != LYS_GROUPING && lys_ingrouping(data_node))) {
                                                                          unsigned int c = 2 * (((struct yang_type *)(yyvsp[-2].backup_token).actual)->type->info.str.pat_count - 1);
                                                                          YANG_ADDELEM(((struct yang_type *)(yyvsp[-2].backup_token).actual)->type->info.str.patterns_pcre, c, "patterns");
                                                                        }
#endif
                                                                        if (yang_read_pattern(trg->ctx, pattern, actual, (yyvsp[-1].str), (yyvsp[0].ch))) {
                                                                          YYABORT;
                                                                        }
                                                                        actual_type = (yyvsp[-2].backup_token).token;
                                                                        actual = (yyvsp[-2].backup_token).actual;
                                                                      }

    break;

  case 182:

    { if (actual_type != EXTENSION_INSTANCE) {
                            if (((struct yang_type *)actual)->base != 0 && ((struct yang_type *)actual)->base != LY_TYPE_STRING) {
                              free(s);
                              LOGVAL(trg->ctx, LYE_SPEC, LY_VLOG_NONE, NULL, "Unexpected pattern statement.");
                              YYABORT;
                            }
                            ((struct yang_type *)actual)->base = LY_TYPE_STRING;
                            YANG_ADDELEM(((struct yang_type *)actual)->type->info.str.patterns,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4623,6 +4623,9 @@
                                                                             !(data_node && data_node->nodetype != LYS_GROUPING && lys_ingrouping(data_node))) {
                                                                           unsigned int c = 2 * (((struct yang_type *)(yyvsp[-2].backup_token).actual)->type->info.str.pat_count - 1);
                                                                           YANG_ADDELEM(((struct yang_type *)(yyvsp[-2].backup_token).actual)->type->info.str.patterns_pcre, c, "patterns");
+                                                                          ++c;
+                                                                          YANG_ADDELEM(((struct yang_type *)(yyvsp[-2].backup_token).actual)->type->info.str.patterns_pcre, c, "patterns");
+                                                                          actual = &(((struct yang_type *)(yyvsp[-2].backup_token).actual)->type->info.str.patterns_pcre)[2 * (((struct yang_type *)(yyvsp[-2].backup_token).actual)->type->info.str.pat_count - 1)];
                                                                         }
 #endif
                                                                         if (yang_read_pattern(trg->ctx, pattern, actual, (yyvsp[-1].str), (yyvsp[0].ch))) {
```
