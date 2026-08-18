# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 1287_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1287_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 962-1002 of the vulnerable file.


    return EXIT_SUCCESS;
}

/**
 * @brief Change the value into its canonical form. In libyang, additionally to the RFC,
 * all identities have their module as a prefix in their canonical form.
 *
 * @param[in] ctx
 * @param[in] type Type of the value.
 * @param[in,out] value Original and then canonical value.
 * @param[in] data1 If \p type is #LY_TYPE_BITS: (struct lys_type_bit **) type bit field,
 *                                #LY_TYPE_DEC64: (int64_t *) parsed digits of the number itself without floating point,
 *                                #LY_TYPE_IDENT: (const char *) local module name (identityref node module),
 *                                #LY_TYPE_INT*: (int64_t *) parsed int number itself,
 *                                #LY_TYPE_UINT*: (uint64_t *) parsed uint number itself,
 *                                otherwise ignored.
 * @param[in] data2 If \p type is #LY_TYPE_BITS: (int *) type bit field length,
 *                                #LY_TYPE_DEC64: (uint8_t *) number of fraction digits (position of the floating point),
 *                                otherwise ignored.
 * @return 1 if a conversion took place, 0 if the value was kept the same.
 */
static int
make_canonical(struct ly_ctx *ctx, int type, const char **value, void *data1, void *data2)
{
    const uint16_t buf_len = 511;
    char buf[buf_len + 1];
    struct lys_type_bit **bits = NULL;
    struct lyxp_expr *exp;
    const char *module_name, *cur_expr, *end;
    int i, j, count;
    int64_t num;
    uint64_t unum;
    uint8_t c;

    switch (type) {
    case LY_TYPE_BITS:
        bits = (struct lys_type_bit **)data1;
        count = *((int *)data2);
        /* in canonical form, the bits are ordered by their position */
        buf[0] = '\0';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -979,7 +979,7 @@
  * @param[in] data2 If \p type is #LY_TYPE_BITS: (int *) type bit field length,
  *                                #LY_TYPE_DEC64: (uint8_t *) number of fraction digits (position of the floating point),
  *                                otherwise ignored.
- * @return 1 if a conversion took place, 0 if the value was kept the same.
+ * @return 1 if a conversion took place, 0 if the value was kept the same, -1 on error.
  */
 static int
 make_canonical(struct ly_ctx *ctx, int type, const char **value, void *data1, void *data2)
@@ -993,6 +993,8 @@
     int64_t num;
     uint64_t unum;
     uint8_t c;
+
+#define LOGBUF(str) LOGERR(ctx, LY_EINVAL, "Value \"%s\" is too long.", str)
 
     switch (type) {
     case LY_TYPE_BITS:
@@ -1006,8 +1008,10 @@
                 continue;
             }
             if (buf[0]) {
+                LY_CHECK_ERR_RETURN(strlen(buf) + 1 + strlen(bits[i]->name) > buf_len, LOGBUF(bits[i]->name), -1);
                 sprintf(buf + strlen(buf), " %s", bits[i]->name);
             } else {
+                LY_CHECK_ERR_RETURN(strlen(bits[i]->name) > buf_len, LOGBUF(bits[i]->name), -1);
                 strcpy(buf, bits[i]->name);
             }
         }
@@ -1025,7 +1029,7 @@
 
     case LY_TYPE_INST:
         exp = lyxp_parse_expr(ctx, *value);
-        LY_CHECK_ERR_RETURN(!exp, LOGINT(ctx), 0);
+        LY_CHECK_ERR_RETURN(!exp, LOGINT(ctx), -1);
 
         module_name = NULL;
         count = 0;
@@ -1035,9 +1039,9 @@
             /* copy WS */
             if (i && ((end = exp->expr + exp->expr_pos[i - 1] + exp->tok_len[i - 1]) != cur_expr)) {
                 if (count + (cur_expr - end) > buf_len) {
-                    LOGINT(ctx);
                     lyxp_expr_free(exp);
-                    return 0;
+                    LOGBUF(end);
+                    return -1;
                 }
                 strncpy(&buf[count], end, cur_expr - end);
                 count += cur_expr - end;
@@ -1051,9 +1055,9 @@
                 if (!module_name || strncmp(cur_expr, module_name, j)) {
                     /* print module name with colon, it does not equal to the parent one */
                     if (count + j > buf_len) {
-                        LOGINT(ctx);
                         lyxp_expr_free(exp);
-                        return 0;
+                        LOGBUF(cur_expr);
+                        return -1;
                     }
                     strncpy(&buf[count], cur_expr, j);
                     count += j;
@@ -1062,17 +1066,17 @@
 
                 /* copy the rest */
                 if (count + (exp->tok_len[i] - j) > buf_len) {
-                    LOGINT(ctx);
                     lyxp_expr_free(exp);
-                    return 0;
+                    LOGBUF(end);
+                    return -1;
                 }
                 strncpy(&buf[count], end, exp->tok_len[i] - j);
                 count += exp->tok_len[i] - j;
             } else {
                 if (count + exp->tok_len[i] > buf_len) {
-                    LOGINT(ctx);
                     lyxp_expr_free(exp);
-                    return 0;
+                    LOGBUF(&exp->expr[exp->expr_pos[i]]);
+                    return -1;
                 }
                 strncpy(&buf[count], &exp->expr[exp->expr_pos[i]], exp->tok_len[i]);
                 count += exp->tok_len[i];
@@ -1081,7 +1085,7 @@
         if (count > buf_len) {
             LOGINT(ctx);
             lyxp_expr_free(exp);
-            return 0;
+            return -1;
         }
         buf[count] = '\0';
 
@@ -1146,6 +1150,8 @@
     }
 
     return 0;
+
+#undef LOGBUF
 }
 
 static const char *
@@ -1412,7 +1418,10 @@
             c = c + len;
         }
 
-        make_canonical(ctx, LY_TYPE_BITS, value_, bits, &type->info.bits.count);
+        if (make_canonical(ctx, LY_TYPE_BITS, value_, bits, &type->info.bits.count) == -1) {
+            free(bits);
+            goto error;
+        }
 
         if (store) {
             /* store the result */
@@ -1470,7 +1479,9 @@
             goto error;
         }
 
-        make_canonical(ctx, LY_TYPE_DEC64, value_, &num, &type->info.dec64.dig);
+        if (make_canonical(ctx, LY_TYPE_DEC64, value_, &num, &type->info.dec64.dig) == -1) {
+            goto error;
+        }
 
         if (store) {
             /* store the result */
@@ -1598,7 +1609,10 @@
             type->parent->flags |= LYS_DFLTJSON;
         }
 
-        make_canonical(ctx, LY_TYPE_IDENT, &value, (void*)lys_main_module(local_mod)->name, NULL);
+        if (make_canonical(ctx, LY_TYPE_IDENT, &value, (void*)lys_main_module(local_mod)->name, NULL) == -1) {
+            lydict_remove(ctx, value);
+            goto error;
+        }
 
         /* replace the old value with the new one (even if they may be the same) */
         lydict_remove(ctx, *value_);
@@ -1651,7 +1665,11 @@
             /* turn logging back on */
             ly_ilo_restore(NULL, prev_ilo, NULL, 0);
         } else {
-            if (make_canonical(ctx, LY_TYPE_INST, &value, NULL, NULL)) {
+            if ((c = make_canonical(ctx, LY_TYPE_INST, &value, NULL, NULL))) {
+                if (c == -1) {
+                    goto error;
+                }
+
                 /* if a change occurred, value was removed from the dictionary so fix the pointers */
                 *value_ = value;
             }
@@ -1749,7 +1767,9 @@
             goto error;
         }
 
-        make_canonical(ctx, LY_TYPE_INT8, value_, &num, NULL);
+        if (make_canonical(ctx, LY_TYPE_INT8, value_, &num, NULL) == -1) {
+            goto error;
+        }
 
         if (store) {
             /* store the result */
@@ -1764,7 +1784,9 @@
             goto error;
         }
 
-        make_canonical(ctx, LY_TYPE_INT16, value_, &num, NULL);
+        if (make_canonical(ctx, LY_TYPE_INT16, value_, &num, NULL) == -1) {
+            goto error;
+        }
 
         if (store) {
             /* store the result */
@@ -1779,7 +1801,9 @@
             goto error;
         }
 
-        make_canonical(ctx, LY_TYPE_INT32, value_, &num, NULL);
+        if (make_canonical(ctx, LY_TYPE_INT32, value_, &num, NULL) == -1) {
+            goto error;
+        }
 
         if (store) {
             /* store the result */
@@ -1795,7 +1819,9 @@
             goto error;
         }
 
-        make_canonical(ctx, LY_TYPE_INT64, value_, &num, NULL);
+        if (make_canonical(ctx, LY_TYPE_INT64, value_, &num, NULL) == -1) {
+            goto error;
+        }
 
         if (store) {
             /* store the result */
@@ -1810,7 +1836,9 @@
             goto error;
         }
 
-        make_canonical(ctx, LY_TYPE_UINT8, value_, &unum, NULL);
+        if (make_canonical(ctx, LY_TYPE_UINT8, value_, &unum, NULL) == -1) {
+            goto error;
+        }
 
         if (store) {
             /* store the result */
@@ -1825,7 +1853,9 @@
             goto error;
         }
 
-        make_canonical(ctx, LY_TYPE_UINT16, value_, &unum, NULL);
+        if (make_canonical(ctx, LY_TYPE_UINT16, value_, &unum, NULL) == -1) {
+            goto error;
+        }
 
         if (store) {
             /* store the result */
@@ -1840,7 +1870,9 @@
             goto error;
         }
 
-        make_canonical(ctx, LY_TYPE_UINT32, value_, &unum, NULL);
+        if (make_canonical(ctx, LY_TYPE_UINT32, value_, &unum, NULL) == -1) {
+            goto error;
+        }
 
         if (store) {
             /* store the result */
@@ -1855,7 +1887,9 @@
             goto error;
         }
 
-        make_canonical(ctx, LY_TYPE_UINT64, value_, &unum, NULL);
+        if (make_canonical(ctx, LY_TYPE_UINT64, value_, &unum, NULL) == -1) {
+            goto error;
+        }
 
         if (store) {
             /* store the result */
```
