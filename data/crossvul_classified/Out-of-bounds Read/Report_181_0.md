# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 181_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `181_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 662-702 of the vulnerable file.

}

/*static int java_fn(RAnal *anal, RAnalFunction *fcn, ut64 addr, ut8 *buf, ut64 len, int reftype) {
	// XXX - this may clash with malloc:// uris because the file name is
	// malloc:// **
	RBinJavaObj *bin = (RBinJavaObj *) get_java_bin_obj (anal);
	RBinJavaField *method = bin ? r_bin_java_get_method_code_attribute_with_addr (bin,  addr) : NULL;
	ut64 loadaddr = bin ? bin->loadaddr : 0;
	IFDBG eprintf ("Analyzing java functions for %s\n", anal->iob.io->fd->name);
	if (method) return analyze_from_code_attr (anal, fcn, method, loadaddr);
	return analyze_from_code_buffer (anal, fcn, addr, buf, len);
}*/

static int java_switch_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
	ut8 op_byte = data[0];
	ut64 offset = addr - java_get_method_start ();
	ut8 pos = (offset+1)%4 ? 1 + 4 - (offset+1)%4 : 1;

	if (op_byte == 0xaa) {
		// handle a table switch condition
		if (pos + 8 > len) {
			return op->size;
		}
		int min_val = (ut32)(UINT (data, pos + 4)),
			max_val = (ut32)(UINT (data, pos + 8));

		ut32 default_loc = (ut32) (UINT (data, pos)), cur_case = 0;
		op->switch_op = r_anal_switch_op_new (addr, min_val, default_loc);
		RAnalCaseOp *caseop = NULL;
		pos += 12;
		if (max_val > min_val && ((max_val - min_val)<(UT16_MAX/4))) {
			//caseop = r_anal_switch_op_add_case(op->switch_op, addr+default_loc, -1, addr+offset);
			for (cur_case = 0; cur_case <= max_val - min_val; pos += 4, cur_case++) {
				//ut32 value = (ut32)(UINT (data, pos));
				if (pos + 4 >= len) {
					// switch is too big cant read further
					break;
				}
				int offset = (int)(ut32)(R_BIN_JAVA_UINT (data, pos));
				caseop = r_anal_switch_op_add_case (op->switch_op,
					addr + pos, cur_case + min_val, addr + offset);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -679,11 +679,11 @@
 
 	if (op_byte == 0xaa) {
 		// handle a table switch condition
-		if (pos + 8 > len) {
+		if (pos + 8 + 8 > len) {
 			return op->size;
 		}
-		int min_val = (ut32)(UINT (data, pos + 4)),
-			max_val = (ut32)(UINT (data, pos + 8));
+		const int min_val = (ut32)(UINT (data, pos + 4));
+		const int max_val = (ut32)(UINT (data, pos + 8));
 
 		ut32 default_loc = (ut32) (UINT (data, pos)), cur_case = 0;
 		op->switch_op = r_anal_switch_op_new (addr, min_val, default_loc);
```
