# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 458_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `458_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 4278-4318 of the vulnerable file.

	{"vmrun", 0, NULL, 0x0f01d8, 3},
	{"vmsave", 0, NULL, 0x0f01db, 3},
	{"vmxoff", 0, NULL, 0x0f01c4, 3},
	{"vmxon", 0, &opvmon, 0},
	{"vzeroall", 0, NULL, 0xc5fc77, 3},
	{"vzeroupper", 0, NULL, 0xc5f877, 3},
	{"wait", 0, NULL, 0x9b, 1},
	{"wbinvd", 0, NULL, 0x0f09, 2},
	{"wrmsr", 0, NULL, 0x0f30, 2},
	{"xadd", 0, &opxadd, 0},
	{"xchg", 0, &opxchg, 0},
	{"xgetbv", 0, NULL, 0x0f01d0, 3},
	{"xlatb", 0, NULL, 0xd7, 1},
	{"xor", 0, &opxor, 0},
	{"xsetbv", 0, NULL, 0x0f01d1, 3},
	{"test", 0, &optest, 0},
	{"null", 0, NULL, 0, 0}
};

static x86newTokenType getToken(const char *str, size_t *begin, size_t *end) {
	// Skip whitespace
	while (begin && isspace ((ut8)str[*begin])) {
		++(*begin);
	}

	if (!str[*begin]) {                // null byte
		*end = *begin;
		return TT_EOF;
	} else if (isalpha ((ut8)str[*begin])) {   // word token
		*end = *begin;
		while (end && isalnum ((ut8)str[*end])) {
			++(*end);
		}
		return TT_WORD;
	} else if (isdigit ((ut8)str[*begin])) {   // number token
		*end = *begin;
		while (end && isalnum ((ut8)str[*end])) {     // accept alphanumeric characters, because hex.
			++(*end);
		}
		return TT_NUMBER;
	} else {                             // special character: [, ], +, *, ...
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4295,21 +4295,26 @@
 };
 
 static x86newTokenType getToken(const char *str, size_t *begin, size_t *end) {
+	if (*begin > strlen (str)) {
+		return TT_EOF;
+	}
 	// Skip whitespace
-	while (begin && isspace ((ut8)str[*begin])) {
+	while (begin && str[*begin] && isspace ((ut8)str[*begin])) {
 		++(*begin);
 	}
 
 	if (!str[*begin]) {                // null byte
 		*end = *begin;
 		return TT_EOF;
-	} else if (isalpha ((ut8)str[*begin])) {   // word token
+	}
+	if (isalpha ((ut8)str[*begin])) {   // word token
 		*end = *begin;
-		while (end && isalnum ((ut8)str[*end])) {
+		while (end && str[*end] && isalnum ((ut8)str[*end])) {
 			++(*end);
 		}
 		return TT_WORD;
-	} else if (isdigit ((ut8)str[*begin])) {   // number token
+	}
+	if (isdigit ((ut8)str[*begin])) {   // number token
 		*end = *begin;
 		while (end && isalnum ((ut8)str[*end])) {     // accept alphanumeric characters, because hex.
 			++(*end);
```
