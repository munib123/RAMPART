# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3946_3
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3946_3`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 125-165 of the vulnerable file.

}

static UINT serial_process_irp_create(SERIAL_DEVICE* serial, IRP* irp)
{
	DWORD DesiredAccess;
	DWORD SharedAccess;
	DWORD CreateDisposition;
	UINT32 PathLength;

	if (Stream_GetRemainingLength(irp->input) < 32)
		return ERROR_INVALID_DATA;

	Stream_Read_UINT32(irp->input, DesiredAccess);     /* DesiredAccess (4 bytes) */
	Stream_Seek_UINT64(irp->input);                    /* AllocationSize (8 bytes) */
	Stream_Seek_UINT32(irp->input);                    /* FileAttributes (4 bytes) */
	Stream_Read_UINT32(irp->input, SharedAccess);      /* SharedAccess (4 bytes) */
	Stream_Read_UINT32(irp->input, CreateDisposition); /* CreateDisposition (4 bytes) */
	Stream_Seek_UINT32(irp->input);                    /* CreateOptions (4 bytes) */
	Stream_Read_UINT32(irp->input, PathLength);        /* PathLength (4 bytes) */

	if (Stream_GetRemainingLength(irp->input) < PathLength)
		return ERROR_INVALID_DATA;

	Stream_Seek(irp->input, PathLength); /* Path (variable) */
	assert(PathLength == 0);             /* MS-RDPESP 2.2.2.2 */
#ifndef _WIN32
	/* Windows 2012 server sends on a first call :
	 *     DesiredAccess     = 0x00100080: SYNCHRONIZE | FILE_READ_ATTRIBUTES
	 *     SharedAccess      = 0x00000007: FILE_SHARE_DELETE | FILE_SHARE_WRITE | FILE_SHARE_READ
	 *     CreateDisposition = 0x00000001: CREATE_NEW
	 *
	 * then Windows 2012 sends :
	 *     DesiredAccess     = 0x00120089: SYNCHRONIZE | READ_CONTROL | FILE_READ_ATTRIBUTES |
	 * FILE_READ_EA | FILE_READ_DATA SharedAccess      = 0x00000007: FILE_SHARE_DELETE |
	 * FILE_SHARE_WRITE | FILE_SHARE_READ CreateDisposition = 0x00000001: CREATE_NEW
	 *
	 * assert(DesiredAccess == (GENERIC_READ | GENERIC_WRITE));
	 * assert(SharedAccess == 0);
	 * assert(CreateDisposition == OPEN_EXISTING);
	 *
	 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -142,10 +142,9 @@
 	Stream_Seek_UINT32(irp->input);                    /* CreateOptions (4 bytes) */
 	Stream_Read_UINT32(irp->input, PathLength);        /* PathLength (4 bytes) */
 
-	if (Stream_GetRemainingLength(irp->input) < PathLength)
+	if (!Stream_SafeSeek(irp->input, PathLength)) /* Path (variable) */
 		return ERROR_INVALID_DATA;
 
-	Stream_Seek(irp->input, PathLength); /* Path (variable) */
 	assert(PathLength == 0);             /* MS-RDPESP 2.2.2.2 */
 #ifndef _WIN32
 	/* Windows 2012 server sends on a first call :
@@ -300,6 +299,7 @@
 {
 	UINT32 Length;
 	UINT64 Offset;
+	void* ptr;
 	DWORD nbWritten = 0;
 
 	if (Stream_GetRemainingLength(irp->input) < 32)
@@ -307,7 +307,9 @@
 
 	Stream_Read_UINT32(irp->input, Length); /* Length (4 bytes) */
 	Stream_Read_UINT64(irp->input, Offset); /* Offset (8 bytes) */
-	Stream_Seek(irp->input, 20);            /* Padding (20 bytes) */
+	if (!Stream_SafeSeek(irp->input, 20))   /* Padding (20 bytes) */
+		return ERROR_INVALID_DATA;
+
 	/* MS-RDPESP 3.2.5.1.5: The Offset field is ignored
 	 * assert(Offset == 0);
 	 *
@@ -317,8 +319,11 @@
 	WLog_Print(serial->log, WLOG_DEBUG, "writing %" PRIu32 " bytes to %s", Length,
 	           serial->device.name);
 
+	ptr = Stream_Pointer(irp->input);
+	if (!Stream_SafeSeek(irp->input, Length))
+		return ERROR_INVALID_DATA;
 	/* FIXME: CommWriteFile to be replaced by WriteFile */
-	if (CommWriteFile(serial->hComm, Stream_Pointer(irp->input), Length, &nbWritten, NULL))
+	if (CommWriteFile(serial->hComm, ptr, Length, &nbWritten, NULL))
 	{
 		irp->IoStatus = STATUS_SUCCESS;
 	}
```
