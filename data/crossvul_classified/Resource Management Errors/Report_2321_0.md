# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 2321_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2321_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 3790-3830 of the vulnerable file.

static const struct opcode group8[] = {
	N, N, N, N,
	F(DstMem | SrcImmByte | NoWrite,		em_bt),
	F(DstMem | SrcImmByte | Lock | PageTable,	em_bts),
	F(DstMem | SrcImmByte | Lock,			em_btr),
	F(DstMem | SrcImmByte | Lock | PageTable,	em_btc),
};

static const struct group_dual group9 = { {
	N, I(DstMem64 | Lock | PageTable, em_cmpxchg8b), N, N, N, N, N, N,
}, {
	N, N, N, N, N, N, N, N,
} };

static const struct opcode group11[] = {
	I(DstMem | SrcImm | Mov | PageTable, em_mov),
	X7(D(Undefined)),
};

static const struct gprefix pfx_0f_ae_7 = {
	I(0, em_clflush), N, N, N,
};

static const struct group_dual group15 = { {
	N, N, N, N, N, N, N, GP(0, &pfx_0f_ae_7),
}, {
	N, N, N, N, N, N, N, N,
} };

static const struct gprefix pfx_0f_6f_0f_7f = {
	I(Mmx, em_mov), I(Sse | Aligned, em_mov), N, I(Sse | Unaligned, em_mov),
};

static const struct gprefix pfx_0f_2b = {
	I(0, em_mov), I(0, em_mov), N, N,
};

static const struct gprefix pfx_0f_28_0f_29 = {
	I(Aligned, em_mov), I(Aligned, em_mov), N, N,
};

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3807,7 +3807,7 @@
 };
 
 static const struct gprefix pfx_0f_ae_7 = {
-	I(0, em_clflush), N, N, N,
+	I(SrcMem | ByteOp, em_clflush), N, N, N,
 };
 
 static const struct group_dual group15 = { {
@@ -4024,10 +4024,11 @@
 	N, I(ImplicitOps | EmulateOnUD, em_syscall),
 	II(ImplicitOps | Priv, em_clts, clts), N,
 	DI(ImplicitOps | Priv, invd), DI(ImplicitOps | Priv, wbinvd), N, N,
-	N, D(ImplicitOps | ModRM), N, N,
+	N, D(ImplicitOps | ModRM | SrcMem | NoAccess), N, N,
 	/* 0x10 - 0x1F */
 	N, N, N, N, N, N, N, N,
-	D(ImplicitOps | ModRM), N, N, N, N, N, N, D(ImplicitOps | ModRM),
+	D(ImplicitOps | ModRM | SrcMem | NoAccess),
+	N, N, N, N, N, N, D(ImplicitOps | ModRM | SrcMem | NoAccess),
 	/* 0x20 - 0x2F */
 	DIP(ModRM | DstMem | Priv | Op3264 | NoMod, cr_read, check_cr_read),
 	DIP(ModRM | DstMem | Priv | Op3264 | NoMod, dr_read, check_dr_read),
```
