# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2861_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2861_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 399-439 of the vulnerable file.

	while (str[i] != ' ' && i < buf_len) {
		tmp[i] = str[i];
		i++;
	}
	tmp[i] = 0;
	for (i = 0; i < 0xff; i++) {
		WasmOpDef *opdef = &opcodes[i];
		if (opdef->txt) {
			if (!strcmp (opdef->txt, tmp)) {
				buf[0] = i;
				return 1;
			}
		}
	}
	return len;
}

int wasm_dis(WasmOp *op, const unsigned char *buf, int buf_len) {
	op->len = 1;
	op->op = buf[0];
	if (op->op > 0xbf) return 1;
	// add support for extension opcodes (SIMD + atomics)
	WasmOpDef *opdef = &opcodes[op->op];
	switch (op->op) {
	case WASM_OP_TRAP:
	case WASM_OP_NOP:
	case WASM_OP_ELSE:
	case WASM_OP_RETURN:
	case WASM_OP_DROP:
	case WASM_OP_SELECT:
	case WASM_OP_I32EQZ: 
	case WASM_OP_I32EQ: 
	case WASM_OP_I32NE: 
	case WASM_OP_I32LTS: 
	case WASM_OP_I32LTU: 
	case WASM_OP_I32GTS: 
	case WASM_OP_I32GTU: 
	case WASM_OP_I32LES: 
	case WASM_OP_I32LEU: 
	case WASM_OP_I32GES: 
	case WASM_OP_I32GEU: 
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -416,7 +416,9 @@
 int wasm_dis(WasmOp *op, const unsigned char *buf, int buf_len) {
 	op->len = 1;
 	op->op = buf[0];
-	if (op->op > 0xbf) return 1;
+	if (op->op > 0xbf) {
+		return 1;
+	}
 	// add support for extension opcodes (SIMD + atomics)
 	WasmOpDef *opdef = &opcodes[op->op];
 	switch (op->op) {
@@ -599,28 +601,37 @@
 		{
 			ut32 count = 0, *table = NULL, def = 0;
 			size_t n = read_u32_leb128 (buf + 1, buf + buf_len, &count);
-			if (!(n > 0 && n < buf_len)) goto err;
-			if (!(table = calloc (count, sizeof (ut32)))) goto err;
+			if (!(n > 0 && n < buf_len)) {
+				goto err;
+			}
+			if (!(table = calloc (count, sizeof (ut32)))) {
+				goto err;
+			}
 			int i = 0;
 			op->len += n;
 			for (i = 0; i < count; i++) {
 				n = read_u32_leb128 (buf + op->len, buf + buf_len, &table[i]);
-				if (!(op->len + n <= buf_len)) goto beach;
+				if (!(op->len + n <= buf_len)) {
+					goto beach;
+				}
 				op->len += n;
 			}
 			n = read_u32_leb128 (buf + op->len, buf + buf_len, &def);
-			if (!(n > 0 && n + op->len < buf_len)) goto beach;
+			if (!(n > 0 && n + op->len < buf_len)) {
+				goto beach;
+			}
 			op->len += n;
 			snprintf (op->txt, R_ASM_BUFSIZE, "%s %d ", opdef->txt, count);
-			for (i = 0; i < count && strlen (op->txt) < R_ASM_BUFSIZE; i++) {
-				snprintf (op->txt + strlen (op->txt), R_ASM_BUFSIZE, "%d ", table[i]);
+			for (i = 0; i < count && strlen (op->txt) + 10 < R_ASM_BUFSIZE; i++) {
+				int optxtlen = strlen (op->txt);
+				snprintf (op->txt + optxtlen, R_ASM_BUFSIZE - optxtlen, "%d ", table[i]);
 			}	
 			snprintf (op->txt + strlen (op->txt), R_ASM_BUFSIZE, "%d", def);
 			free (table);
 			break;
 			beach:
-				free (table);
-				goto err;
+			free (table);
+			goto err;
 		}
 		break;
 	case WASM_OP_CALLINDIRECT:
@@ -744,4 +755,3 @@
 	snprintf (op->txt, R_ASM_BUFSIZE, "invalid");
 	return op->len;
 }
-
```
