# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 5569_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5569_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 914-954 of the vulnerable file.

		goto fault;
	}
	session->rd_size = req->rd_size;

	hid = hid_allocate_device();
	if (IS_ERR(hid)) {
		err = PTR_ERR(hid);
		goto fault;
	}

	session->hid = hid;

	hid->driver_data = session;

	hid->bus     = BUS_BLUETOOTH;
	hid->vendor  = req->vendor;
	hid->product = req->product;
	hid->version = req->version;
	hid->country = req->country;

	strncpy(hid->name, req->name, 128);

	snprintf(hid->phys, sizeof(hid->phys), "%pMR",
		 &bt_sk(session->ctrl_sock->sk)->src);

	snprintf(hid->uniq, sizeof(hid->uniq), "%pMR",
		 &bt_sk(session->ctrl_sock->sk)->dst);

	hid->dev.parent = &session->conn->dev;
	hid->ll_driver = &hidp_hid_driver;

	hid->hid_get_raw_report = hidp_get_raw_report;
	hid->hid_output_raw_report = hidp_output_raw_report;

	/* True if device is blacklisted in drivers/hid/hid-core.c */
	if (hid_ignore(hid)) {
		hid_destroy_device(session->hid);
		session->hid = NULL;
		return -ENODEV;
	}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -931,7 +931,7 @@
 	hid->version = req->version;
 	hid->country = req->country;
 
-	strncpy(hid->name, req->name, 128);
+	strncpy(hid->name, req->name, sizeof(req->name) - 1);
 
 	snprintf(hid->phys, sizeof(hid->phys), "%pMR",
 		 &bt_sk(session->ctrl_sock->sk)->src);
```
