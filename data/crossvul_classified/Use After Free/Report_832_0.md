# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 832_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `832_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 2068-2108 of the vulnerable file.

	rv = ipmi_register_smi(&handlers,
			       new_smi,
			       new_smi->io.dev,
			       new_smi->io.slave_addr);
	if (rv) {
		dev_err(new_smi->io.dev,
			"Unable to register device: error %d\n",
			rv);
		goto out_err;
	}

	/* Don't increment till we know we have succeeded. */
	smi_num++;

	dev_info(new_smi->io.dev, "IPMI %s interface initialized\n",
		 si_to_str[new_smi->io.si_type]);

	WARN_ON(new_smi->io.dev->init_name != NULL);

 out_err:
	kfree(init_name);
	return rv;
}

static int init_ipmi_si(void)
{
	struct smi_info *e;
	enum ipmi_addr_src type = SI_INVALID;

	if (initialized)
		return 0;

	pr_info("IPMI System Interface driver\n");

	/* If the user gave us a device, they presumably want us to use it */
	if (!ipmi_si_hardcode_find_bmc())
		goto do_scan;

	ipmi_si_platform_init();

	ipmi_si_pci_init();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2085,6 +2085,11 @@
 	WARN_ON(new_smi->io.dev->init_name != NULL);
 
  out_err:
+	if (rv && new_smi->io.io_cleanup) {
+		new_smi->io.io_cleanup(&new_smi->io);
+		new_smi->io.io_cleanup = NULL;
+	}
+
 	kfree(init_name);
 	return rv;
 }
```
