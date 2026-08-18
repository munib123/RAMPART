# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 308_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `308_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 71-113 of the vulnerable file.

	printk(KERN_INFO "Booting paravirtualized kernel on %s\n",
	       pv_info.name);
}

/* Undefined instruction for dealing with missing ops pointers. */
static const unsigned char ud2a[] = { 0x0f, 0x0b };

struct branch {
	unsigned char opcode;
	u32 delta;
} __attribute__((packed));

unsigned paravirt_patch_call(void *insnbuf,
			     const void *target, u16 tgt_clobbers,
			     unsigned long addr, u16 site_clobbers,
			     unsigned len)
{
	struct branch *b = insnbuf;
	unsigned long delta = (unsigned long)target - (addr+5);

	if (tgt_clobbers & ~site_clobbers)
		return len;	/* target would clobber too much for this site */
	if (len < 5)
		return len;	/* call too long for patch site */

	b->opcode = 0xe8; /* call */
	b->delta = delta;
	BUILD_BUG_ON(sizeof(*b) != 5);

	return 5;
}

unsigned paravirt_patch_jmp(void *insnbuf, const void *target,
			    unsigned long addr, unsigned len)
{
	struct branch *b = insnbuf;
	unsigned long delta = (unsigned long)target - (addr+5);

	if (len < 5)
		return len;	/* call too long for patch site */

	b->opcode = 0xe9;	/* jmp */
	b->delta = delta;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -88,10 +88,12 @@
 	struct branch *b = insnbuf;
 	unsigned long delta = (unsigned long)target - (addr+5);
 
-	if (tgt_clobbers & ~site_clobbers)
-		return len;	/* target would clobber too much for this site */
-	if (len < 5)
+	if (len < 5) {
+#ifdef CONFIG_RETPOLINE
+		WARN_ONCE("Failing to patch indirect CALL in %ps\n", (void *)addr);
+#endif
 		return len;	/* call too long for patch site */
+	}
 
 	b->opcode = 0xe8; /* call */
 	b->delta = delta;
@@ -106,8 +108,12 @@
 	struct branch *b = insnbuf;
 	unsigned long delta = (unsigned long)target - (addr+5);
 
-	if (len < 5)
+	if (len < 5) {
+#ifdef CONFIG_RETPOLINE
+		WARN_ONCE("Failing to patch indirect JMP in %ps\n", (void *)addr);
+#endif
 		return len;	/* call too long for patch site */
+	}
 
 	b->opcode = 0xe9;	/* jmp */
 	b->delta = delta;
```
