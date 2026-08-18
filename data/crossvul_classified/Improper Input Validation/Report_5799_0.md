# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5799_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5799_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 494-534 of the vulnerable file.

	}
	/*
	 *	Allocate and initialize a Fib then setup a SRB command
	 */
	if (!(srbfib = aac_fib_alloc(dev))) {
		return -ENOMEM;
	}
	aac_fib_init(srbfib);
	/* raw_srb FIB is not FastResponseCapable */
	srbfib->hw_fib_va->header.XferState &= ~cpu_to_le32(FastResponseCapable);

	srbcmd = (struct aac_srb*) fib_data(srbfib);

	memset(sg_list, 0, sizeof(sg_list)); /* cleanup may take issue */
	if(copy_from_user(&fibsize, &user_srb->count,sizeof(u32))){
		dprintk((KERN_DEBUG"aacraid: Could not copy data size from user\n"));
		rcode = -EFAULT;
		goto cleanup;
	}

	if (fibsize > (dev->max_fib_size - sizeof(struct aac_fibhdr))) {
		rcode = -EINVAL;
		goto cleanup;
	}

	user_srbcmd = kmalloc(fibsize, GFP_KERNEL);
	if (!user_srbcmd) {
		dprintk((KERN_DEBUG"aacraid: Could not make a copy of the srb\n"));
		rcode = -ENOMEM;
		goto cleanup;
	}
	if(copy_from_user(user_srbcmd, user_srb,fibsize)){
		dprintk((KERN_DEBUG"aacraid: Could not copy srb from user\n"));
		rcode = -EFAULT;
		goto cleanup;
	}

	user_reply = arg+fibsize;

	flags = user_srbcmd->flags; /* from user in cpu order */
	// Fix up srb for endian and force some values
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -511,7 +511,8 @@
 		goto cleanup;
 	}
 
-	if (fibsize > (dev->max_fib_size - sizeof(struct aac_fibhdr))) {
+	if ((fibsize < (sizeof(struct user_aac_srb) - sizeof(struct user_sgentry))) ||
+	    (fibsize > (dev->max_fib_size - sizeof(struct aac_fibhdr)))) {
 		rcode = -EINVAL;
 		goto cleanup;
 	}
```
