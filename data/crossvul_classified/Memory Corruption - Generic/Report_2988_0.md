# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2988_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2988_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1286-1326 of the vulnerable file.


	if (regs[regno].type != PTR_TO_STACK) {
		/* Allow zero-byte read from NULL, regardless of pointer type */
		if (zero_size_allowed && access_size == 0 &&
		    register_is_null(regs[regno]))
			return 0;

		verbose(env, "R%d type=%s expected=%s\n", regno,
			reg_type_str[regs[regno].type],
			reg_type_str[PTR_TO_STACK]);
		return -EACCES;
	}

	/* Only allow fixed-offset stack reads */
	if (!tnum_is_const(regs[regno].var_off)) {
		char tn_buf[48];

		tnum_strn(tn_buf, sizeof(tn_buf), regs[regno].var_off);
		verbose(env, "invalid variable stack read R%d var_off=%s\n",
			regno, tn_buf);
	}
	off = regs[regno].off + regs[regno].var_off.value;
	if (off >= 0 || off < -MAX_BPF_STACK || off + access_size > 0 ||
	    access_size < 0 || (access_size == 0 && !zero_size_allowed)) {
		verbose(env, "invalid stack type R%d off=%d access_size=%d\n",
			regno, off, access_size);
		return -EACCES;
	}

	if (env->prog->aux->stack_depth < -off)
		env->prog->aux->stack_depth = -off;

	if (meta && meta->raw_mode) {
		meta->access_size = access_size;
		meta->regno = regno;
		return 0;
	}

	for (i = 0; i < access_size; i++) {
		slot = -(off + i) - 1;
		spi = slot / BPF_REG_SIZE;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1303,6 +1303,7 @@
 		tnum_strn(tn_buf, sizeof(tn_buf), regs[regno].var_off);
 		verbose(env, "invalid variable stack read R%d var_off=%s\n",
 			regno, tn_buf);
+		return -EACCES;
 	}
 	off = regs[regno].off + regs[regno].var_off.value;
 	if (off >= 0 || off < -MAX_BPF_STACK || off + access_size > 0 ||
```
