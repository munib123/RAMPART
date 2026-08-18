# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3946_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3946_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 461-501 of the vulnerable file.

	else
	{
		printjob->Close(printjob);
	}

	Stream_Zero(irp->output, 4); /* Padding(4) */
	return irp->Complete(irp);
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT printer_process_irp_write(PRINTER_DEVICE* printer_dev, IRP* irp)
{
	UINT32 Length;
	UINT64 Offset;
	rdpPrintJob* printjob = NULL;
	UINT error = CHANNEL_RC_OK;
	Stream_Read_UINT32(irp->input, Length);
	Stream_Read_UINT64(irp->input, Offset);
	Stream_Seek(irp->input, 20); /* Padding */

	if (printer_dev->printer)
		printjob = printer_dev->printer->FindPrintJob(printer_dev->printer, irp->FileId);

	if (!printjob)
	{
		irp->IoStatus = STATUS_UNSUCCESSFUL;
		Length = 0;
	}
	else
	{
		error = printjob->Write(printjob, Stream_Pointer(irp->input), Length);
	}

	if (error)
	{
		WLog_ERR(TAG, "printjob->Write failed with error %" PRIu32 "!", error);
		return error;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -478,10 +478,16 @@
 	UINT64 Offset;
 	rdpPrintJob* printjob = NULL;
 	UINT error = CHANNEL_RC_OK;
+	void* ptr;
+
+	if (Stream_GetRemainingLength(irp->input) < 32)
+		return ERROR_INVALID_DATA;
 	Stream_Read_UINT32(irp->input, Length);
 	Stream_Read_UINT64(irp->input, Offset);
 	Stream_Seek(irp->input, 20); /* Padding */
-
+	ptr = Stream_Pointer(irp->input);
+	if (!Stream_SafeSeek(irp->input, Length))
+		return ERROR_INVALID_DATA;
 	if (printer_dev->printer)
 		printjob = printer_dev->printer->FindPrintJob(printer_dev->printer, irp->FileId);
 
@@ -492,7 +498,7 @@
 	}
 	else
 	{
-		error = printjob->Write(printjob, Stream_Pointer(irp->input), Length);
+		error = printjob->Write(printjob, ptr, Length);
 	}
 
 	if (error)
```
