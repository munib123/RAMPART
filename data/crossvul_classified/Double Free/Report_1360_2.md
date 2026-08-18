# CrossVul Fix Pair: Double Free in c
**Pair ID:** 1360_2
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1360_2`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 3418-3458 of the vulnerable file.

                                           memcpy(((struct lys_include *)actual)->rev, s, LY_REV_SIZE-1);
                                           free(s);
                                           s = NULL;
                                           (yyval.i) = 1;
                                         }

    break;

  case 45:

    { backup_type = actual_type;
                                  actual_type = REVISION_DATE_KEYWORD;
                                }

    break;

  case 47:

    { (yyval.token) = actual_type;
                                         if (is_ext_instance) {
                                           if (yang_read_extcomplex_str(trg, ext_instance, "belongs-to", ext_name, s,
                                                                        0, LY_STMT_BELONGSTO)) {
                                             YYABORT;
                                           }
                                         } else {
                                           if (param->submodule->prefix) {
                                             LOGVAL(trg->ctx, LYE_TOOMANY, LY_VLOG_NONE, NULL, "belongs-to", "submodule");
                                             free(s);
                                             YYABORT;
                                           }
                                           if (!ly_strequal(s, param->submodule->belongsto->name, 0)) {
                                             LOGVAL(trg->ctx, LYE_INARG, LY_VLOG_NONE, NULL, s, "belongs-to");
                                             free(s);
                                             YYABORT;
                                           }
                                           free(s);
                                         }
                                         s = NULL;
                                         actual_type = BELONGS_TO_KEYWORD;
                                       }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3435,7 +3435,7 @@
 
     { (yyval.token) = actual_type;
                                          if (is_ext_instance) {
-                                           if (yang_read_extcomplex_str(trg, ext_instance, "belongs-to", ext_name, s,
+                                           if (yang_read_extcomplex_str(trg, ext_instance, "belongs-to", ext_name, &s,
                                                                         0, LY_STMT_BELONGSTO)) {
                                              YYABORT;
                                            }
@@ -3461,7 +3461,7 @@
   case 48:
 
     { if (is_ext_instance) {
-                         if (yang_read_extcomplex_str(trg, ext_instance, "prefix", "belongs-to", s,
+                         if (yang_read_extcomplex_str(trg, ext_instance, "prefix", "belongs-to", &s,
                                                       LY_STMT_BELONGSTO, LY_STMT_PREFIX)) {
                            YYABORT;
                          }
@@ -3802,7 +3802,7 @@
 
     { (yyval.token) = actual_type;
                                    if (is_ext_instance) {
-                                     if (yang_read_extcomplex_str(trg, ext_instance, "argument", ext_name, s,
+                                     if (yang_read_extcomplex_str(trg, ext_instance, "argument", ext_name, &s,
                                                                   0, LY_STMT_ARGUMENT)) {
                                        YYABORT;
                                      }
@@ -8442,7 +8442,7 @@
 
   case 792:
 
-    { if (yang_read_extcomplex_str(trg, ext_instance, "prefix", ext_name, s,
+    { if (yang_read_extcomplex_str(trg, ext_instance, "prefix", ext_name, &s,
                                                                   0, LY_STMT_PREFIX)) {
                                        YYABORT;
                                      }
@@ -8452,7 +8452,7 @@
 
   case 793:
 
-    { if (yang_read_extcomplex_str(trg, ext_instance, "description", ext_name, s,
+    { if (yang_read_extcomplex_str(trg, ext_instance, "description", ext_name, &s,
                                                                        0, LY_STMT_DESCRIPTION)) {
                                             YYABORT;
                                           }
@@ -8462,7 +8462,7 @@
 
   case 794:
 
-    { if (yang_read_extcomplex_str(trg, ext_instance, "reference", ext_name, s,
+    { if (yang_read_extcomplex_str(trg, ext_instance, "reference", ext_name, &s,
                                                                      0, LY_STMT_REFERENCE)) {
                                           YYABORT;
                                         }
@@ -8472,7 +8472,7 @@
 
   case 795:
 
-    { if (yang_read_extcomplex_str(trg, ext_instance, "units", ext_name, s,
+    { if (yang_read_extcomplex_str(trg, ext_instance, "units", ext_name, &s,
                                                                      0, LY_STMT_UNITS)) {
                                       YYABORT;
                                     }
@@ -8482,7 +8482,7 @@
 
   case 796:
 
-    { if (yang_read_extcomplex_str(trg, ext_instance, "base", ext_name, s,
+    { if (yang_read_extcomplex_str(trg, ext_instance, "base", ext_name, &s,
                                                                 0, LY_STMT_BASE)) {
                                      YYABORT;
                                    }
@@ -8492,7 +8492,7 @@
 
   case 797:
 
-    { if (yang_read_extcomplex_str(trg, ext_instance, "contact", ext_name, s,
+    { if (yang_read_extcomplex_str(trg, ext_instance, "contact", ext_name, &s,
                                                                      0, LY_STMT_CONTACT)) {
                                         YYABORT;
                                       }
@@ -8502,7 +8502,7 @@
 
   case 798:
 
-    { if (yang_read_extcomplex_str(trg, ext_instance, "default", ext_name, s,
+    { if (yang_read_extcomplex_str(trg, ext_instance, "default", ext_name, &s,
                                                                      0, LY_STMT_DEFAULT)) {
                                         YYABORT;
                                       }
@@ -8512,7 +8512,7 @@
 
   case 799:
 
-    { if (yang_read_extcomplex_str(trg, ext_instance, "error-message", ext_name, s,
+    { if (yang_read_extcomplex_str(trg, ext_instance, "error-message", ext_name, &s,
                                                                          0, LY_STMT_ERRMSG)) {
                                               YYABORT;
                                             }
@@ -8522,7 +8522,7 @@
 
   case 800:
 
-    { if (yang_read_extcomplex_str(trg, ext_instance, "error-app-tag", ext_name, s,
+    { if (yang_read_extcomplex_str(trg, ext_instance, "error-app-tag", ext_name, &s,
                                                                          0, LY_STMT_ERRTAG)) {
                                               YYABORT;
                                             }
@@ -8532,7 +8532,7 @@
 
   case 801:
 
-    { if (yang_read_extcomplex_str(trg, ext_instance, "key", ext_name, s,
+    { if (yang_read_extcomplex_str(trg, ext_instance, "key", ext_name, &s,
                                                                0, LY_STMT_KEY)) {
                                     YYABORT;
                                   }
@@ -8542,7 +8542,7 @@
 
   case 802:
 
-    { if (yang_read_extcomplex_str(trg, ext_instance, "namespace", ext_name, s,
+    { if (yang_read_extcomplex_str(trg, ext_instance, "namespace", ext_name, &s,
                                                                      0, LY_STMT_NAMESPACE)) {
                                           YYABORT;
                                         }
@@ -8552,7 +8552,7 @@
 
   case 803:
 
-    { if (yang_read_extcomplex_str(trg, ext_instance, "organization", ext_name, s,
+    { if (yang_read_extcomplex_str(trg, ext_instance, "organization", ext_name, &s,
                                                                         0, LY_STMT_ORGANIZATION)) {
                                              YYABORT;
                                            }
@@ -8562,7 +8562,7 @@
 
   case 804:
 
-    { if (yang_read_extcomplex_str(trg, ext_instance, "path", ext_name, s,
+    { if (yang_read_extcomplex_str(trg, ext_instance, "path", ext_name, &s,
                                                                 0, LY_STMT_PATH)) {
                                      YYABORT;
                                    }
@@ -8572,7 +8572,7 @@
 
   case 805:
 
-    { if (yang_read_extcomplex_str(trg, ext_instance, "presence", ext_name, s,
+    { if (yang_read_extcomplex_str(trg, ext_instance, "presence", ext_name, &s,
                                                                     0, LY_STMT_PRESENCE)) {
                                          YYABORT;
                                        }
@@ -8582,7 +8582,7 @@
 
   case 806:
 
-    { if (yang_read_extcomplex_str(trg, ext_instance, "revision-date", ext_name, s,
+    { if (yang_read_extcomplex_str(trg, ext_instance, "revision-date", ext_name, &s,
                                                                          0, LY_STMT_REVISIONDATE)) {
                                               YYABORT;
                                             }
```
