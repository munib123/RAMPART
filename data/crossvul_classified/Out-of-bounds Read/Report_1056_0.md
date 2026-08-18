# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 1056_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1056_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 815-855 of the vulnerable file.

	if (strcmp(ses->server->vals->version_string,
		   SMB3ANY_VERSION_STRING) == 0) {
		if (rsp->DialectRevision == cpu_to_le16(SMB20_PROT_ID)) {
			cifs_dbg(VFS,
				"SMB2 dialect returned but not requested\n");
			return -EIO;
		} else if (rsp->DialectRevision == cpu_to_le16(SMB21_PROT_ID)) {
			cifs_dbg(VFS,
				"SMB2.1 dialect returned but not requested\n");
			return -EIO;
		}
	} else if (strcmp(ses->server->vals->version_string,
		   SMBDEFAULT_VERSION_STRING) == 0) {
		if (rsp->DialectRevision == cpu_to_le16(SMB20_PROT_ID)) {
			cifs_dbg(VFS,
				"SMB2 dialect returned but not requested\n");
			return -EIO;
		} else if (rsp->DialectRevision == cpu_to_le16(SMB21_PROT_ID)) {
			/* ops set to 3.0 by default for default so update */
			ses->server->ops = &smb21_operations;
		} else if (rsp->DialectRevision == cpu_to_le16(SMB311_PROT_ID))
			ses->server->ops = &smb311_operations;
	} else if (le16_to_cpu(rsp->DialectRevision) !=
				ses->server->vals->protocol_id) {
		/* if requested single dialect ensure returned dialect matched */
		cifs_dbg(VFS, "Illegal 0x%x dialect returned: not requested\n",
			le16_to_cpu(rsp->DialectRevision));
		return -EIO;
	}

	cifs_dbg(FYI, "mode 0x%x\n", rsp->SecurityMode);

	if (rsp->DialectRevision == cpu_to_le16(SMB20_PROT_ID))
		cifs_dbg(FYI, "negotiated smb2.0 dialect\n");
	else if (rsp->DialectRevision == cpu_to_le16(SMB21_PROT_ID))
		cifs_dbg(FYI, "negotiated smb2.1 dialect\n");
	else if (rsp->DialectRevision == cpu_to_le16(SMB30_PROT_ID))
		cifs_dbg(FYI, "negotiated smb3.0 dialect\n");
	else if (rsp->DialectRevision == cpu_to_le16(SMB302_PROT_ID))
		cifs_dbg(FYI, "negotiated smb3.02 dialect\n");
	else if (rsp->DialectRevision == cpu_to_le16(SMB311_PROT_ID))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -832,8 +832,11 @@
 		} else if (rsp->DialectRevision == cpu_to_le16(SMB21_PROT_ID)) {
 			/* ops set to 3.0 by default for default so update */
 			ses->server->ops = &smb21_operations;
-		} else if (rsp->DialectRevision == cpu_to_le16(SMB311_PROT_ID))
+			ses->server->vals = &smb21_values;
+		} else if (rsp->DialectRevision == cpu_to_le16(SMB311_PROT_ID)) {
 			ses->server->ops = &smb311_operations;
+			ses->server->vals = &smb311_values;
+		}
 	} else if (le16_to_cpu(rsp->DialectRevision) !=
 				ses->server->vals->protocol_id) {
 		/* if requested single dialect ensure returned dialect matched */
```
