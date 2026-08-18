# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2953_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2953_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1050-1090 of the vulnerable file.

		/* Special case, because of NET_IP_ALIGN. Given metadata sits
		 * right in front, treat it the very same way.
		 */
		return check_pkt_ptr_alignment(env, reg, off, size, strict);
	case PTR_TO_MAP_VALUE:
		pointer_desc = "value ";
		break;
	case PTR_TO_CTX:
		pointer_desc = "context ";
		break;
	case PTR_TO_STACK:
		pointer_desc = "stack ";
		break;
	default:
		break;
	}
	return check_generic_ptr_alignment(env, reg, pointer_desc, off, size,
					   strict);
}

/* check whether memory at (regno + off) is accessible for t = (read | write)
 * if t==write, value_regno is a register which value is stored into memory
 * if t==read, value_regno is a register which will receive the value from memory
 * if t==write && value_regno==-1, some unknown value is stored into memory
 * if t==read && value_regno==-1, don't care what we read from memory
 */
static int check_mem_access(struct bpf_verifier_env *env, int insn_idx, u32 regno, int off,
			    int bpf_size, enum bpf_access_type t,
			    int value_regno)
{
	struct bpf_verifier_state *state = env->cur_state;
	struct bpf_reg_state *regs = cur_regs(env);
	struct bpf_reg_state *reg = regs + regno;
	int size, err = 0;

	size = bpf_size_to_bytes(bpf_size);
	if (size < 0)
		return size;

	/* alignment checks will add in reg->off themselves */
	err = check_ptr_alignment(env, reg, off, size);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1067,6 +1067,29 @@
 					   strict);
 }
 
+/* truncate register to smaller size (in bytes)
+ * must be called with size < BPF_REG_SIZE
+ */
+static void coerce_reg_to_size(struct bpf_reg_state *reg, int size)
+{
+	u64 mask;
+
+	/* clear high bits in bit representation */
+	reg->var_off = tnum_cast(reg->var_off, size);
+
+	/* fix arithmetic bounds */
+	mask = ((u64)1 << (size * 8)) - 1;
+	if ((reg->umin_value & ~mask) == (reg->umax_value & ~mask)) {
+		reg->umin_value &= mask;
+		reg->umax_value &= mask;
+	} else {
+		reg->umin_value = 0;
+		reg->umax_value = mask;
+	}
+	reg->smin_value = reg->umin_value;
+	reg->smax_value = reg->umax_value;
+}
+
 /* check whether memory at (regno + off) is accessible for t = (read | write)
  * if t==write, value_regno is a register which value is stored into memory
  * if t==read, value_regno is a register which will receive the value from memory
@@ -1200,9 +1223,7 @@
 	if (!err && size < BPF_REG_SIZE && value_regno >= 0 && t == BPF_READ &&
 	    regs[value_regno].type == SCALAR_VALUE) {
 		/* b/h/w load zero-extends, mark upper bits as known 0 */
-		regs[value_regno].var_off =
-			tnum_cast(regs[value_regno].var_off, size);
-		__update_reg_bounds(&regs[value_regno]);
+		coerce_reg_to_size(&regs[value_regno], size);
 	}
 	return err;
 }
@@ -1772,14 +1793,6 @@
 	return 0;
 }
 
-static void coerce_reg_to_32(struct bpf_reg_state *reg)
-{
-	/* clear high 32 bits */
-	reg->var_off = tnum_cast(reg->var_off, 4);
-	/* Update bounds */
-	__update_reg_bounds(reg);
-}
-
 static bool signed_add_overflows(s64 a, s64 b)
 {
 	/* Do the add in u64, where overflow is well-defined */
@@ -2017,8 +2030,8 @@
 
 	if (BPF_CLASS(insn->code) != BPF_ALU64) {
 		/* 32-bit ALU ops are (32,32)->64 */
-		coerce_reg_to_32(dst_reg);
-		coerce_reg_to_32(&src_reg);
+		coerce_reg_to_size(dst_reg, 4);
+		coerce_reg_to_size(&src_reg, 4);
 	}
 	smin_val = src_reg.smin_value;
 	smax_val = src_reg.smax_value;
@@ -2398,10 +2411,7 @@
 					return -EACCES;
 				}
 				mark_reg_unknown(env, regs, insn->dst_reg);
-				/* high 32 bits are known zero. */
-				regs[insn->dst_reg].var_off = tnum_cast(
-						regs[insn->dst_reg].var_off, 4);
-				__update_reg_bounds(&regs[insn->dst_reg]);
+				coerce_reg_to_size(&regs[insn->dst_reg], 4);
 			}
 		} else {
 			/* case: R = imm
```
