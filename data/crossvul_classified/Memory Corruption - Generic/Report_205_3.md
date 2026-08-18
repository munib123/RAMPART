# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 205_3
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `205_3`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 61-101 of the vulnerable file.

 */
#define PRED_FUNC_START			OP_LE
#define PRED_FUNC_MAX			(OP_BAND - PRED_FUNC_START)

#define ERRORS								\
	C(NONE,			"No error"),				\
	C(INVALID_OP,		"Invalid operator"),			\
	C(TOO_MANY_OPEN,	"Too many '('"),			\
	C(TOO_MANY_CLOSE,	"Too few '('"),				\
	C(MISSING_QUOTE,	"Missing matching quote"),		\
	C(OPERAND_TOO_LONG,	"Operand too long"),			\
	C(EXPECT_STRING,	"Expecting string field"),		\
	C(EXPECT_DIGIT,		"Expecting numeric field"),		\
	C(ILLEGAL_FIELD_OP,	"Illegal operation for field type"),	\
	C(FIELD_NOT_FOUND,	"Field not found"),			\
	C(ILLEGAL_INTVAL,	"Illegal integer value"),		\
	C(BAD_SUBSYS_FILTER,	"Couldn't find or set field in one of a subsystem's events"), \
	C(TOO_MANY_PREDS,	"Too many terms in predicate expression"), \
	C(INVALID_FILTER,	"Meaningless filter expression"),	\
	C(IP_FIELD_ONLY,	"Only 'ip' field is supported for function trace"), \
	C(INVALID_VALUE,	"Invalid value (did you forget quotes)?"),

#undef C
#define C(a, b)		FILT_ERR_##a

enum { ERRORS };

#undef C
#define C(a, b)		b

static char *err_text[] = { ERRORS };

/* Called after a '!' character but "!=" and "!~" are not "not"s */
static bool is_not(const char *str)
{
	switch (str[1]) {
	case '=':
	case '~':
		return false;
	}
	return true;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -78,7 +78,8 @@
 	C(TOO_MANY_PREDS,	"Too many terms in predicate expression"), \
 	C(INVALID_FILTER,	"Meaningless filter expression"),	\
 	C(IP_FIELD_ONLY,	"Only 'ip' field is supported for function trace"), \
-	C(INVALID_VALUE,	"Invalid value (did you forget quotes)?"),
+	C(INVALID_VALUE,	"Invalid value (did you forget quotes)?"), \
+	C(NO_FILTER,		"No filter found"),
 
 #undef C
 #define C(a, b)		FILT_ERR_##a
@@ -547,6 +548,13 @@
 	if (top != op_stack) {
 		/* Too many '(' */
 		parse_error(pe, FILT_ERR_TOO_MANY_OPEN, ptr - str);
+		goto out_free;
+	}
+
+	if (!N) {
+		/* No program? */
+		ret = -EINVAL;
+		parse_error(pe, FILT_ERR_NO_FILTER, ptr - str);
 		goto out_free;
 	}
 
```
