# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3293_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3293_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 50-90 of the vulnerable file.

	size_t n;
	ut32 tmp;
	if (!(n = consume_u32 (buf, max, &tmp, offset)) || n > 1) {
		return 0;
	}
	*out = (st8)(tmp & 0x7f);
	return 1;	
}

static size_t consume_str (ut8 *buf, ut8 *max, size_t sz, char *out, ut32 *offset) {
	if (!buf || !max || !out || !sz) {
		return 0;
	}
	if (!(buf + sz < max)) {
		return 0;
	}
	strncpy ((char*)out, (char*)buf, R_MIN (R_BIN_WASM_STRING_LENGTH-1, sz));
	if (offset) *offset += sz;
	return sz;
}
static size_t consume_init_expr (ut8 *buf, ut8 *max, ut8 eoc, void *out, ut32 *offset) {
	ut32 i = 0;
	while (buf + i < max && buf[i] != eoc) {
		// TODO: calc the expresion with the bytcode (ESIL?)
		i += 1;
	}
	if (buf[i] != eoc) {
		return 0;
	}
	if (offset) {
		*offset += i + 1;
	}
	return i + 1;
}

static size_t consume_locals (ut8 *buf, ut8 *max, ut32 count, RBinWasmCodeEntry *out, ut32 *offset) {
	ut32 i = 0, j = 0;
	if (count < 1) return 0;
	// memory leak
	if (!(out->locals = (struct r_bin_wasm_local_entry_t*) malloc (sizeof(struct r_bin_wasm_local_entry_t) * count))) {
		return 0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -67,11 +67,12 @@
 	if (offset) *offset += sz;
 	return sz;
 }
+
 static size_t consume_init_expr (ut8 *buf, ut8 *max, ut8 eoc, void *out, ut32 *offset) {
 	ut32 i = 0;
 	while (buf + i < max && buf[i] != eoc) {
 		// TODO: calc the expresion with the bytcode (ESIL?)
-		i += 1;
+		i++;
 	}
 	if (buf[i] != eoc) {
 		return 0;
@@ -448,9 +449,78 @@
 }
 
 static RList *r_bin_wasm_get_data_entries (RBinWasmObj *bin, RBinWasmSection *sec) {
-
 	RList *ret = NULL;
 	RBinWasmDataEntry *ptr = NULL;
+	ut32 len =  sec->payload_len;
+
+	if (!(ret = r_list_newf ((RListFree)free))) {
+		return NULL;
+	}
+
+	ut8* buf = bin->buf->buf + (ut32)sec->payload_data;
+	int buflen = bin->buf->length - (ut32)sec->payload_data;
+	ut32 count = sec->count;
+	ut32 i = 0, r = 0;
+	size_t n = 0;
+
+	while (i < len && len < buflen && r < count) {
+		if (!(ptr = R_NEW0 (RBinWasmDataEntry))) {
+			return ret;
+		}
+		if (!(consume_u32 (buf + i, buf + len, &ptr->index, &i))) {
+			goto beach;
+		}
+		if (i + 4 >= buflen) {
+			goto beach;
+		}
+		if (!(n = consume_init_expr (buf + i, buf + len, R_BIN_WASM_END_OF_CODE, NULL, &i))) {
+			goto beach;
+		}
+		ptr->offset.len = n;
+		if (!(consume_u32 (buf + i, buf + len, &ptr->size, &i))) {	
+			goto beach;
+		}
+		if (i + 4 >= buflen) {
+			goto beach;
+		}
+		ptr->data = sec->payload_data + i;
+
+		r_list_append (ret, ptr);
+
+		r += 1;
+
+	}
+	return ret;
+beach:
+	free (ptr);
+	return ret;
+}
+
+static RBinWasmStartEntry *r_bin_wasm_get_start (RBinWasmObj *bin, RBinWasmSection *sec) {
+
+	RBinWasmStartEntry *ptr;	
+
+	if (!(ptr = R_NEW0 (RBinWasmStartEntry))) {
+		return NULL;
+	}
+
+	ut8* buf = bin->buf->buf + (ut32)sec->payload_data;
+	ut32 len =  sec->payload_len;
+	ut32 i = 0;
+
+	if (!(consume_u32 (buf + i, buf + len, &ptr->index, &i))) {
+		free (ptr);
+		return NULL;
+	}
+
+	return ptr;
+
+}
+
+static RList *r_bin_wasm_get_memory_entries (RBinWasmObj *bin, RBinWasmSection *sec) {
+
+	RList *ret = NULL;
+	RBinWasmMemoryEntry *ptr = NULL;
 
 	if (!(ret = r_list_newf ((RListFree)free))) {
 		return NULL;
@@ -460,32 +530,17 @@
 	ut32 len =  sec->payload_len;
 	ut32 count = sec->count;
 	ut32 i = 0, r = 0;
-	size_t n = 0;
 
 	while (i < len && r < count) {
 
-		if (!(ptr = R_NEW0 (RBinWasmDataEntry))) {
-			return ret;
-		}
-
-		if (!(consume_u32 (buf + i, buf + len, &ptr->index, &i))) {
-			free (ptr);
-			return ret;
-		}
-
-		if (!(n = consume_init_expr (buf + i, buf + len, R_BIN_WASM_END_OF_CODE, NULL, &i))) {
-			free (ptr);
-			return ret;
-		}
-
-		ptr->offset.len = n;
-
-		if (!(consume_u32 (buf + i, buf + len, &ptr->size, &i))) {	
-			free (ptr);
-			return ret;
-		}
-
-		ptr->data = sec->payload_data + i;
+		if (!(ptr = R_NEW0 (RBinWasmMemoryEntry))) {
+			return ret;
+		}
+
+		if (!(consume_limits (buf + i, buf + len, &ptr->limits, &i))) {
+			free (ptr);
+			return ret;
+		}
 
 		r_list_append (ret, ptr);
 
@@ -496,31 +551,10 @@
 	return ret;
 }
 
-static RBinWasmStartEntry *r_bin_wasm_get_start (RBinWasmObj *bin, RBinWasmSection *sec) {
-
-	RBinWasmStartEntry *ptr;	
-
-	if (!(ptr = R_NEW0 (RBinWasmStartEntry))) {
-		return NULL;
-	}
-
-	ut8* buf = bin->buf->buf + (ut32)sec->payload_data;
-	ut32 len =  sec->payload_len;
-	ut32 i = 0;
-
-	if (!(consume_u32 (buf + i, buf + len, &ptr->index, &i))) {
-		free (ptr);
-		return NULL;
-	}
-
-	return ptr;
-
-}
-
-static RList *r_bin_wasm_get_memory_entries (RBinWasmObj *bin, RBinWasmSection *sec) {
+static RList *r_bin_wasm_get_table_entries (RBinWasmObj *bin, RBinWasmSection *sec) {
 
 	RList *ret = NULL;
-	RBinWasmMemoryEntry *ptr = NULL;
+	RBinWasmTableEntry *ptr = NULL;
 
 	if (!(ret = r_list_newf ((RListFree)free))) {
 		return NULL;
@@ -533,7 +567,12 @@
 
 	while (i < len && r < count) {
 
-		if (!(ptr = R_NEW0 (RBinWasmMemoryEntry))) {
+		if (!(ptr = R_NEW0 (RBinWasmTableEntry))) {
+			return ret;
+		}
+
+		if (!(consume_u8 (buf + i, buf + len, &ptr->element_type, &i))) {
+			free (ptr);
 			return ret;
 		}
 
@@ -551,122 +590,72 @@
 	return ret;
 }
 
-static RList *r_bin_wasm_get_table_entries (RBinWasmObj *bin, RBinWasmSection *sec) {
-
+static RList *r_bin_wasm_get_global_entries (RBinWasmObj *bin, RBinWasmSection *sec) {
 	RList *ret = NULL;
-	RBinWasmTableEntry *ptr = NULL;
+	RBinWasmGlobalEntry *ptr = NULL;
 
 	if (!(ret = r_list_newf ((RListFree)free))) {
 		return NULL;
 	}
 
 	ut8* buf = bin->buf->buf + (ut32)sec->payload_data;
+	int buflen = bin->buf->length - (ut32)sec->payload_data;
 	ut32 len =  sec->payload_len;
 	ut32 count = sec->count;
 	ut32 i = 0, r = 0;
 
-	while (i < len && r < count) {
-
-		if (!(ptr = R_NEW0 (RBinWasmTableEntry))) {
-			return ret;
-		}
-
-		if (!(consume_u8 (buf + i, buf + len, &ptr->element_type, &i))) {
-			free (ptr);
-			return ret;
-		}
-
-		if (!(consume_limits (buf + i, buf + len, &ptr->limits, &i))) {
-			free (ptr);
-			return ret;
-		}
-
+	while (i < len && len < buflen && r < count) {
+		if (!(ptr = R_NEW0 (RBinWasmGlobalEntry))) {
+			return ret;
+		}
+
+		if (len + 8 > buflen || !(consume_u8 (buf + i, buf + len, (ut8*)&ptr->content_type, &i))) {
+			goto beach;
+		}
+		if (len + 8 > buflen || !(consume_u8 (buf + i, buf + len, &ptr->mutability, &i))) {
+			goto beach;
+		}
+		if (len + 8 > buflen || !(consume_init_expr (buf + i, buf + len, R_BIN_WASM_END_OF_CODE, NULL, &i))) {
+			goto beach;
+		}
 		r_list_append (ret, ptr);
-
-		r += 1;
-
-	}
-
-	return ret;
-}
-
-static RList *r_bin_wasm_get_global_entries (RBinWasmObj *bin, RBinWasmSection *sec) {
+		r++;
+	}
+	return ret;
+beach:
+	free (ptr);
+	return ret;
+}
+
+static RList *r_bin_wasm_get_element_entries (RBinWasmObj *bin, RBinWasmSection *sec) {
 	RList *ret = NULL;
-	RBinWasmGlobalEntry *ptr = NULL;
-	int buflen = bin->buf->length;
-	if (sec->payload_data + 32 > buflen) {
-		return NULL;
-	}
+	RBinWasmElementEntry *ptr = NULL;
 
 	if (!(ret = r_list_newf ((RListFree)free))) {
 		return NULL;
 	}
 
 	ut8* buf = bin->buf->buf + (ut32)sec->payload_data;
+	int buflen = bin->buf->length - (ut32)sec->payload_data;
 	ut32 len =  sec->payload_len;
 	ut32 count = sec->count;
 	ut32 i = 0, r = 0;
 
 	while (i < len && len < buflen && r < count) {
-		if (!(ptr = R_NEW0 (RBinWasmGlobalEntry))) {
-			return ret;
-		}
-
-		if (len + 8 > buflen || !(consume_u8 (buf + i, buf + len, (ut8*)&ptr->content_type, &i))) {
+		if (!(ptr = R_NEW0 (RBinWasmElementEntry))) {
+			return ret;
+		}
+		if (!(consume_u32 (buf + i, buf + len, &ptr->index, &i))) {
 			goto beach;
 		}
-		if (len + 8 > buflen || !(consume_u8 (buf + i, buf + len, &ptr->mutability, &i))) {
+		if (!(consume_init_expr (buf + i, buf + len, R_BIN_WASM_END_OF_CODE, NULL, &i))) {
 			goto beach;
 		}
-		if (len + 8 > buflen || !(consume_init_expr (buf + i, buf + len, R_BIN_WASM_END_OF_CODE, NULL, &i))) {
+		if (!(consume_u32 (buf + i, buf + len, &ptr->num_elem, &i))) {
 			goto beach;
 		}
-		r_list_append (ret, ptr);
-		r++;
-	}
-	return ret;
-beach:
-	free (ptr);
-	return ret;
-}
-
-static RList *r_bin_wasm_get_element_entries (RBinWasmObj *bin, RBinWasmSection *sec) {
-
-	RList *ret = NULL;
-	RBinWasmElementEntry *ptr = NULL;
-
-	if (!(ret = r_list_newf ((RListFree)free))) {
-		return NULL;
-	}
-
-	ut8* buf = bin->buf->buf + (ut32)sec->payload_data;
-	ut32 len =  sec->payload_len;
-	ut32 count = sec->count;
-	ut32 i = 0, r = 0;
-
-	while (i < len && r < count) {
-
-		if (!(ptr = R_NEW0 (RBinWasmElementEntry))) {
-			return ret;
-		}
-
-		if (!(consume_u32 (buf + i, buf + len, &ptr->index, &i))) {
-			free (ptr);
-			return ret;
-		}
-
-		if (!(consume_init_expr (buf + i, buf + len, R_BIN_WASM_END_OF_CODE, NULL, &i))) {
-			free (ptr);
-			return ret;
-		}
-
-		if (!(consume_u32 (buf + i, buf + len, &ptr->num_elem, &i))) {
-			free (ptr);
-			return ret;
-		}
-
 		ut32 j = 0;
-		while (i < len && j < ptr->num_elem	) {
+		while (i < len && j < ptr->num_elem) {
 			// TODO: allocate space and fill entry
 			ut32 e;
 			if (!(consume_u32 (buf + i, buf + len, &e, &i))) {
@@ -674,13 +663,13 @@
... (diff truncated)
```
