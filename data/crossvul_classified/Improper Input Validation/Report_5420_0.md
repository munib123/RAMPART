# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5420_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5420_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 4669-4709 of the vulnerable file.

	CLOSE_A;
	if (h_env->envc == 0 ||
	    (h_env->envc_real < h_env->nenv &&
	     envs[h_env->envc].env != HTML_DL &&
	     envs[h_env->envc].env != HTML_DL_COMPACT)) {
	    PUSH_ENV(HTML_DL);
	}
	if (h_env->envc > 0) {
	    flushline(h_env, obuf,
		      envs[h_env->envc - 1].indent, 0, h_env->limit);
	}
	if (!(obuf->flag & RB_IN_DT)) {
	    HTMLlineproc1("<b>", h_env);
	    obuf->flag |= RB_IN_DT;
	}
	obuf->flag |= RB_IGNORE_P;
	return 1;
    case HTML_DD:
	CLOSE_A;
	CLOSE_DT;
	if (envs[h_env->envc].env == HTML_DL_COMPACT) {
	    if (obuf->pos > envs[h_env->envc].indent)
		flushline(h_env, obuf, envs[h_env->envc].indent, 0,
			  h_env->limit);
	    else
		push_spaces(obuf, 1, envs[h_env->envc].indent - obuf->pos);
	}
	else
	    flushline(h_env, obuf, envs[h_env->envc].indent, 0, h_env->limit);
	/* obuf->flag |= RB_IGNORE_P; */
	return 1;
    case HTML_TITLE:
	close_anchor(h_env, obuf);
	process_title(tag);
	obuf->flag |= RB_TITLE;
	obuf->end_tag = HTML_N_TITLE;
	return 1;
    case HTML_N_TITLE:
	if (!(obuf->flag & RB_TITLE))
	    return 1;
	obuf->flag &= ~RB_TITLE;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4686,6 +4686,12 @@
     case HTML_DD:
 	CLOSE_A;
 	CLOSE_DT;
+	if (h_env->envc == 0 ||
+	    (h_env->envc_real < h_env->nenv &&
+	     envs[h_env->envc].env != HTML_DL &&
+	     envs[h_env->envc].env != HTML_DL_COMPACT)) {
+	    PUSH_ENV(HTML_DL);
+	}
 	if (envs[h_env->envc].env == HTML_DL_COMPACT) {
 	    if (obuf->pos > envs[h_env->envc].indent)
 		flushline(h_env, obuf, envs[h_env->envc].indent, 0,
```
