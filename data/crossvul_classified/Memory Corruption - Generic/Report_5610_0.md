# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5610_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5610_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 14587-14628 of the vulnerable file.

				      PCI_VPD_RO_KEYWORD_MFR_ID);
	if (j > 0) {
		len = pci_vpd_info_field_size(&vpd_data[j]);

		j += PCI_VPD_INFO_FLD_HDR_SIZE;
		if (j + len > block_end || len != 4 ||
		    memcmp(&vpd_data[j], "1028", 4))
			goto partno;

		j = pci_vpd_find_info_keyword(vpd_data, i, rosize,
					      PCI_VPD_RO_KEYWORD_VENDOR0);
		if (j < 0)
			goto partno;

		len = pci_vpd_info_field_size(&vpd_data[j]);

		j += PCI_VPD_INFO_FLD_HDR_SIZE;
		if (j + len > block_end)
			goto partno;

		memcpy(tp->fw_ver, &vpd_data[j], len);
		strncat(tp->fw_ver, " bc ", vpdlen - len - 1);
	}

partno:
	i = pci_vpd_find_info_keyword(vpd_data, i, rosize,
				      PCI_VPD_RO_KEYWORD_PARTNO);
	if (i < 0)
		goto out_not_found;

	len = pci_vpd_info_field_size(&vpd_data[i]);

	i += PCI_VPD_INFO_FLD_HDR_SIZE;
	if (len > TG3_BPN_SIZE ||
	    (len + i) > vpdlen)
		goto out_not_found;

	memcpy(tp->board_part_number, &vpd_data[i], len);

out_not_found:
	kfree(vpd_data);
	if (tp->board_part_number[0])
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14604,8 +14604,11 @@
 		if (j + len > block_end)
 			goto partno;
 
-		memcpy(tp->fw_ver, &vpd_data[j], len);
-		strncat(tp->fw_ver, " bc ", vpdlen - len - 1);
+		if (len >= sizeof(tp->fw_ver))
+			len = sizeof(tp->fw_ver) - 1;
+		memset(tp->fw_ver, 0, sizeof(tp->fw_ver));
+		snprintf(tp->fw_ver, sizeof(tp->fw_ver), "%.*s bc ", len,
+			 &vpd_data[j]);
 	}
 
 partno:
```
