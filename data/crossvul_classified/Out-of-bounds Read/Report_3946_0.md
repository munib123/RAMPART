# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3946_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3946_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 314-354 of the vulnerable file.

		else
		{
			Stream_Write_UINT32(irp->output, Length);
			Stream_Seek(irp->output, Length);
		}
	}

	return irp->Complete(irp);
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT drive_process_irp_write(DRIVE_DEVICE* drive, IRP* irp)
{
	DRIVE_FILE* file;
	UINT32 Length;
	UINT64 Offset;

	if (!drive || !irp || !irp->input || !irp->output || !irp->Complete)
		return ERROR_INVALID_PARAMETER;

	if (Stream_GetRemainingLength(irp->input) < 32)
		return ERROR_INVALID_DATA;

	Stream_Read_UINT32(irp->input, Length);
	Stream_Read_UINT64(irp->input, Offset);
	Stream_Seek(irp->input, 20); /* Padding */
	file = drive_get_file_by_id(drive, irp->FileId);

	if (!file)
	{
		irp->IoStatus = STATUS_UNSUCCESSFUL;
		Length = 0;
	}
	else if (!drive_file_seek(file, Offset))
	{
		irp->IoStatus = drive_map_windows_err(GetLastError());
		Length = 0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -331,6 +331,7 @@
 	DRIVE_FILE* file;
 	UINT32 Length;
 	UINT64 Offset;
+	void* ptr;
 
 	if (!drive || !irp || !irp->input || !irp->output || !irp->Complete)
 		return ERROR_INVALID_PARAMETER;
@@ -341,6 +342,9 @@
 	Stream_Read_UINT32(irp->input, Length);
 	Stream_Read_UINT64(irp->input, Offset);
 	Stream_Seek(irp->input, 20); /* Padding */
+	ptr = Stream_Pointer(irp->input);
+	if (!Stream_SafeSeek(irp->input, Length))
+		return ERROR_INVALID_DATA;
 	file = drive_get_file_by_id(drive, irp->FileId);
 
 	if (!file)
@@ -353,7 +357,7 @@
 		irp->IoStatus = drive_map_windows_err(GetLastError());
 		Length = 0;
 	}
-	else if (!drive_file_write(file, Stream_Pointer(irp->input), Length))
+	else if (!drive_file_write(file, ptr, Length))
 	{
 		irp->IoStatus = drive_map_windows_err(GetLastError());
 		Length = 0;
```
