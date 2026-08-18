# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 832_1
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `832_1`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 64-105 of the vulnerable file.

		release_mem_region(addr + idx * io->regspacing,
				   io->regsize);
}

static void mem_cleanup(struct si_sm_io *io)
{
	if (io->addr) {
		iounmap(io->addr);
		mem_region_cleanup(io, io->io_size);
	}
}

int ipmi_si_mem_setup(struct si_sm_io *io)
{
	unsigned long addr = io->addr_data;
	int           mapsize, idx;

	if (!addr)
		return -ENODEV;

	io->io_cleanup = mem_cleanup;

	/*
	 * Figure out the actual readb/readw/readl/etc routine to use based
	 * upon the register size.
	 */
	switch (io->regsize) {
	case 1:
		io->inputb = intf_mem_inb;
		io->outputb = intf_mem_outb;
		break;
	case 2:
		io->inputb = intf_mem_inw;
		io->outputb = intf_mem_outw;
		break;
	case 4:
		io->inputb = intf_mem_inl;
		io->outputb = intf_mem_outl;
		break;
#ifdef readq
	case 8:
		io->inputb = mem_inq;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -81,8 +81,6 @@
 	if (!addr)
 		return -ENODEV;
 
-	io->io_cleanup = mem_cleanup;
-
 	/*
 	 * Figure out the actual readb/readw/readl/etc routine to use based
 	 * upon the register size.
@@ -141,5 +139,8 @@
 		mem_region_cleanup(io, io->io_size);
 		return -EIO;
 	}
+
+	io->io_cleanup = mem_cleanup;
+
 	return 0;
 }
```
