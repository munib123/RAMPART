# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 832_2
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `832_2`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 51-92 of the vulnerable file.

static void port_cleanup(struct si_sm_io *io)
{
	unsigned int addr = io->addr_data;
	int          idx;

	if (addr) {
		for (idx = 0; idx < io->io_size; idx++)
			release_region(addr + idx * io->regspacing,
				       io->regsize);
	}
}

int ipmi_si_port_setup(struct si_sm_io *io)
{
	unsigned int addr = io->addr_data;
	int          idx;

	if (!addr)
		return -ENODEV;

	io->io_cleanup = port_cleanup;

	/*
	 * Figure out the actual inb/inw/inl/etc routine to use based
	 * upon the register size.
	 */
	switch (io->regsize) {
	case 1:
		io->inputb = port_inb;
		io->outputb = port_outb;
		break;
	case 2:
		io->inputb = port_inw;
		io->outputb = port_outw;
		break;
	case 4:
		io->inputb = port_inl;
		io->outputb = port_outl;
		break;
	default:
		dev_warn(io->dev, "Invalid register size: %d\n",
			 io->regsize);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -68,8 +68,6 @@
 	if (!addr)
 		return -ENODEV;
 
-	io->io_cleanup = port_cleanup;
-
 	/*
 	 * Figure out the actual inb/inw/inl/etc routine to use based
 	 * upon the register size.
@@ -109,5 +107,8 @@
 			return -EIO;
 		}
 	}
+
+	io->io_cleanup = port_cleanup;
+
 	return 0;
 }
```
