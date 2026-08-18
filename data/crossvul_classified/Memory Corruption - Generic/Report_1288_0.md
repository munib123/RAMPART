# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 1288_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1288_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 1004-1044 of the vulnerable file.

        buf[0] = '\0';
        for (i = 0; i < count; i++) {
            if (!bits[i]) {
                /* bit not set */
                continue;
            }
            if (buf[0]) {
                LY_CHECK_ERR_RETURN(strlen(buf) + 1 + strlen(bits[i]->name) > buf_len, LOGBUF(bits[i]->name), -1);
                sprintf(buf + strlen(buf), " %s", bits[i]->name);
            } else {
                LY_CHECK_ERR_RETURN(strlen(bits[i]->name) > buf_len, LOGBUF(bits[i]->name), -1);
                strcpy(buf, bits[i]->name);
            }
        }
        break;

    case LY_TYPE_IDENT:
        module_name = (const char *)data1;
        /* identity must always have a prefix */
        if (!strchr(*value, ':')) {
            sprintf(buf, "%s:%s", module_name, *value);
        } else {
            strcpy(buf, *value);
        }
        break;

    case LY_TYPE_INST:
        exp = lyxp_parse_expr(ctx, *value);
        LY_CHECK_ERR_RETURN(!exp, LOGINT(ctx), -1);

        module_name = NULL;
        count = 0;
        for (i = 0; (unsigned)i < exp->used; ++i) {
            cur_expr = &exp->expr[exp->expr_pos[i]];

            /* copy WS */
            if (i && ((end = exp->expr + exp->expr_pos[i - 1] + exp->tok_len[i - 1]) != cur_expr)) {
                if (count + (cur_expr - end) > buf_len) {
                    lyxp_expr_free(exp);
                    LOGBUF(end);
                    return -1;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1021,8 +1021,10 @@
         module_name = (const char *)data1;
         /* identity must always have a prefix */
         if (!strchr(*value, ':')) {
+            LY_CHECK_ERR_RETURN(strlen(module_name) + 1 + strlen(*value) > buf_len, LOGBUF(*value), -1);
             sprintf(buf, "%s:%s", module_name, *value);
         } else {
+            LY_CHECK_ERR_RETURN(strlen(*value) > buf_len, LOGBUF(*value), -1);
             strcpy(buf, *value);
         }
         break;
```
