# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3173_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3173_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 292-333 of the vulnerable file.

	return NULL;
}

// TODO: fix this, now has more registers that it should
// https://github.com/android/platform_dalvik/blob/0641c2b4836fae3ee8daf6c0af45c316c84d5aeb/libdex/DexDebugInfo.cpp#L312
// https://github.com/android/platform_dalvik/blob/0641c2b4836fae3ee8daf6c0af45c316c84d5aeb/libdex/DexDebugInfo.cpp#L141
static void dex_parse_debug_item(RBinFile *binfile, RBinDexObj *bin,
				  RBinDexClass *c, int MI, int MA, int paddr, int ins_size,
				  int insns_size, char *class_name, int regsz,
				  int debug_info_off) {
	struct r_bin_t *rbin = binfile->rbin;
	const ut8 *p4 = r_buf_get_at (binfile->buf, debug_info_off, NULL);
	const ut8 *p4_end = p4 + binfile->buf->length - debug_info_off;
	ut64 line_start;
	ut64 parameters_size;
	ut64 param_type_idx;
	ut16 argReg = regsz - ins_size;
	ut64 source_file_idx = c->source_file;
	RList *params, *debug_positions, *emitted_debug_locals = NULL; 
	bool keep = true;
	if (argReg >= regsz) {
		//return; // this return breaks tests
	}
	p4 = r_uleb128 (p4, p4_end - p4, &line_start);
	p4 = r_uleb128 (p4, p4_end - p4, &parameters_size);
	// TODO: check when we should use source_file
	// The state machine consists of five registers
	ut32 address = 0;
	ut32 line = line_start;
	if (!(debug_positions = r_list_newf ((RListFree)free))) {
		return;	
	}
	if (!(emitted_debug_locals = r_list_newf ((RListFree)free))) {
		r_list_free (debug_positions);
		return;
	}

	struct dex_debug_local_t debug_locals[regsz];
	memset (debug_locals, 0, sizeof (struct dex_debug_local_t) * regsz);
	if (!(MA & 0x0008)) {
		debug_locals[argReg].name = "this";
		debug_locals[argReg].descriptor = r_str_newf("%s;", class_name);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -309,8 +309,8 @@
 	ut64 source_file_idx = c->source_file;
 	RList *params, *debug_positions, *emitted_debug_locals = NULL; 
 	bool keep = true;
-	if (argReg >= regsz) {
-		//return; // this return breaks tests
+	if (argReg > regsz) {
+		return; // this return breaks tests
 	}
 	p4 = r_uleb128 (p4, p4_end - p4, &line_start);
 	p4 = r_uleb128 (p4, p4_end - p4, &parameters_size);
```
