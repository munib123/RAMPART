# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in c
**Pair ID:** 3326_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3326_0`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```c
Lines 4401-4441 of the vulnerable file.

    int shift;
    TCGMemOp ot, aflag, dflag;
    int modrm, reg, rm, mod, op, opreg, val;
    target_ulong next_eip, tval;
    int rex_w, rex_r;

    s->pc_start = s->pc = pc_start;
    prefixes = 0;
    s->override = -1;
    rex_w = -1;
    rex_r = 0;
#ifdef TARGET_X86_64
    s->rex_x = 0;
    s->rex_b = 0;
    x86_64_hregs = 0;
#endif
    s->rip_offset = 0; /* for relative ip address */
    s->vex_l = 0;
    s->vex_v = 0;
 next_byte:
    b = cpu_ldub_code(env, s->pc);
    s->pc++;
    /* Collect prefixes.  */
    switch (b) {
    case 0xf3:
        prefixes |= PREFIX_REPZ;
        goto next_byte;
    case 0xf2:
        prefixes |= PREFIX_REPNZ;
        goto next_byte;
    case 0xf0:
        prefixes |= PREFIX_LOCK;
        goto next_byte;
    case 0x2e:
        s->override = R_CS;
        goto next_byte;
    case 0x36:
        s->override = R_SS;
        goto next_byte;
    case 0x3e:
        s->override = R_DS;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4418,6 +4418,13 @@
     s->vex_l = 0;
     s->vex_v = 0;
  next_byte:
+    /* x86 has an upper limit of 15 bytes for an instruction. Since we
+     * do not want to decode and generate IR for an illegal
+     * instruction, the following check limits the instruction size to
+     * 25 bytes: 14 prefix + 1 opc + 6 (modrm+sib+ofs) + 4 imm */
+    if (s->pc - pc_start > 14) {
+        goto illegal_op;
+    }
     b = cpu_ldub_code(env, s->pc);
     s->pc++;
     /* Collect prefixes.  */
```
