# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 1070_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1070_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 3893-3933 of the vulnerable file.

	      if (!PEND) PFETCH(c);
	    }
	    else {
	      if (c == ')') break;
	    }
	  }
	  goto start;
	}
#ifdef USE_PERL_SUBEXP_CALL
	/* (?&name), (?n), (?R), (?0), (?+n), (?-n) */
	c = PPEEK;
	if ((c == '&' || c == 'R' || ONIGENC_IS_CODE_DIGIT(enc, c)) &&
	    IS_SYNTAX_OP2(env->syntax, ONIG_SYN_OP2_QMARK_SUBEXP_CALL)) {
	  /* (?&name), (?n), (?R), (?0) */
	  int gnum;
	  UChar *name;
	  UChar *name_end;

	  if (c == 'R' || c == '0') {
	    PINC;   /* skip 'R' / '0' */
	    if (!PPEEK_IS(')')) return ONIGERR_INVALID_GROUP_NAME;
	    PINC;   /* skip ')' */
	    name_end = name = p;
	    gnum = 0;
	  }
	  else {
	    int numref = 1;
	    if (c == '&') {     /* (?&name) */
	      PINC;
	      numref = 0;       /* don't allow number name */
	    }
	    name = p;
	    r = fetch_name((OnigCodePoint )'(', &p, end, &name_end, env, &gnum, numref);
	    if (r < 0) return r;
	  }

	  tok->type = TK_CALL;
	  tok->u.call.name     = name;
	  tok->u.call.name_end = name_end;
	  tok->u.call.gnum     = gnum;
	  tok->u.call.rel      = 0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3910,7 +3910,11 @@
 
 	  if (c == 'R' || c == '0') {
 	    PINC;   /* skip 'R' / '0' */
-	    if (!PPEEK_IS(')')) return ONIGERR_INVALID_GROUP_NAME;
+	    if (!PPEEK_IS(')')) {
+	      r = ONIGERR_INVALID_GROUP_NAME;
+	      onig_scan_env_set_error_string(env, r, p - 1, p + 1);
+	      return r;
+	    }
 	    PINC;   /* skip ')' */
 	    name_end = name = p;
 	    gnum = 0;
```
