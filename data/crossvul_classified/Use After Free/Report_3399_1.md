# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 3399_1
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3399_1`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 79-119 of the vulnerable file.

	if (r_bin_file_set_cur_by_fd (core->bin, bin_fd)) {
		r_core_bin_set_cur (core, r_core_bin_cur (core));
		return true;
	}
	return false;
}

R_API int r_core_bin_set_by_name(RCore *core, const char * name) {
	if (r_bin_file_set_cur_by_name (core->bin, name)) {
		r_core_bin_set_cur (core, r_core_bin_cur (core));
		return true;
	}
	return false;
}

R_API int r_core_bin_set_env(RCore *r, RBinFile *binfile) {
	RBinObject *binobj = binfile ? binfile->o: NULL;
	RBinInfo *info = binobj ? binobj->info: NULL;
	if (info) {
		int va = info->has_va;
		const char * arch = info->arch;
		ut16 bits = info->bits;
		ut64 baseaddr = r_bin_get_baddr (r->bin);
		/* Hack to make baddr work on some corner */
		r_config_set_i (r->config, "io.va",
			(binobj->info)? binobj->info->has_va: 0);
		r_config_set_i (r->config, "bin.baddr", baseaddr);
		r_config_set (r->config, "asm.arch", arch);
		r_config_set_i (r->config, "asm.bits", bits);
		r_config_set (r->config, "anal.arch", arch);
		if (info->cpu && *info->cpu) {
			r_config_set (r->config, "anal.cpu", info->cpu);
		} else {
			r_config_set (r->config, "anal.cpu", arch);
		}
		r_asm_use (r->assembler, arch);
		r_core_bin_info (r, R_CORE_BIN_ACC_ALL, R_CORE_BIN_SET, va, NULL, NULL);
		r_core_bin_set_cur (r, binfile);
		return true;
	}
	return false;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -96,7 +96,8 @@
 	RBinInfo *info = binobj ? binobj->info: NULL;
 	if (info) {
 		int va = info->has_va;
-		const char * arch = info->arch;
+		char * arch = strdup(info->arch);
+		char * cpu = info->cpu? strdup(info->cpu): NULL;
 		ut16 bits = info->bits;
 		ut64 baseaddr = r_bin_get_baddr (r->bin);
 		/* Hack to make baddr work on some corner */
@@ -106,14 +107,16 @@
 		r_config_set (r->config, "asm.arch", arch);
 		r_config_set_i (r->config, "asm.bits", bits);
 		r_config_set (r->config, "anal.arch", arch);
-		if (info->cpu && *info->cpu) {
-			r_config_set (r->config, "anal.cpu", info->cpu);
+		if (cpu && *cpu) {
+			r_config_set (r->config, "anal.cpu", cpu);
 		} else {
 			r_config_set (r->config, "anal.cpu", arch);
 		}
 		r_asm_use (r->assembler, arch);
 		r_core_bin_info (r, R_CORE_BIN_ACC_ALL, R_CORE_BIN_SET, va, NULL, NULL);
 		r_core_bin_set_cur (r, binfile);
+		free (cpu);
+		free (arch);
 		return true;
 	}
 	return false;
```
