# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 1492_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1492_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 628-668 of the vulnerable file.

		if (BAD_ADDR(error))
			goto out;
	}

	error = load_addr;
out:
	return error;
}

/*
 * These are the functions used to load ELF style executables and shared
 * libraries.  There is no binary dependent code anywhere else.
 */

#ifndef STACK_RND_MASK
#define STACK_RND_MASK (0x7ff >> (PAGE_SHIFT - 12))	/* 8MB of VA */
#endif

static unsigned long randomize_stack_top(unsigned long stack_top)
{
	unsigned int random_variable = 0;

	if ((current->flags & PF_RANDOMIZE) &&
		!(current->personality & ADDR_NO_RANDOMIZE)) {
		random_variable = get_random_int() & STACK_RND_MASK;
		random_variable <<= PAGE_SHIFT;
	}
#ifdef CONFIG_STACK_GROWSUP
	return PAGE_ALIGN(stack_top) + random_variable;
#else
	return PAGE_ALIGN(stack_top) - random_variable;
#endif
}

static int load_elf_binary(struct linux_binprm *bprm)
{
	struct file *interpreter = NULL; /* to shut gcc up */
 	unsigned long load_addr = 0, load_bias = 0;
	int load_addr_set = 0;
	char * elf_interpreter = NULL;
	unsigned long error;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -645,11 +645,12 @@
 
 static unsigned long randomize_stack_top(unsigned long stack_top)
 {
-	unsigned int random_variable = 0;
+	unsigned long random_variable = 0;
 
 	if ((current->flags & PF_RANDOMIZE) &&
 		!(current->personality & ADDR_NO_RANDOMIZE)) {
-		random_variable = get_random_int() & STACK_RND_MASK;
+		random_variable = (unsigned long) get_random_int();
+		random_variable &= STACK_RND_MASK;
 		random_variable <<= PAGE_SHIFT;
 	}
 #ifdef CONFIG_STACK_GROWSUP
```
