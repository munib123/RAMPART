# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3947_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3947_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 66-106 of the vulnerable file.


	int file;
	char* path;
	UINT32 id;

	HANDLE thread;
	wMessageQueue* queue;
	rdpContext* rdpcontext;
};
typedef struct _PARALLEL_DEVICE PARALLEL_DEVICE;

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT parallel_process_irp_create(PARALLEL_DEVICE* parallel, IRP* irp)
{
	char* path = NULL;
	int status;
	UINT32 PathLength;
	Stream_Seek(irp->input, 28);
	/* DesiredAccess(4) AllocationSize(8), FileAttributes(4) */
	/* SharedAccess(4) CreateDisposition(4), CreateOptions(4) */
	Stream_Read_UINT32(irp->input, PathLength);
	status = ConvertFromUnicode(CP_UTF8, 0, (WCHAR*)Stream_Pointer(irp->input), PathLength / 2,
	                            &path, 0, NULL, NULL);

	if (status < 1)
		if (!(path = (char*)calloc(1, 1)))
		{
			WLog_ERR(TAG, "calloc failed!");
			return CHANNEL_RC_NO_MEMORY;
		}

	parallel->id = irp->devman->id_sequence++;
	parallel->file = open(parallel->path, O_RDWR);

	if (parallel->file < 0)
	{
		irp->IoStatus = STATUS_ACCESS_DENIED;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -83,13 +83,19 @@
 {
 	char* path = NULL;
 	int status;
+	WCHAR* ptr;
 	UINT32 PathLength;
-	Stream_Seek(irp->input, 28);
+	if (!Stream_SafeSeek(irp->input, 28))
+		return ERROR_INVALID_DATA;
 	/* DesiredAccess(4) AllocationSize(8), FileAttributes(4) */
 	/* SharedAccess(4) CreateDisposition(4), CreateOptions(4) */
+	if (Stream_GetRemainingLength(irp->input) < 4)
+		return ERROR_INVALID_DATA;
 	Stream_Read_UINT32(irp->input, PathLength);
-	status = ConvertFromUnicode(CP_UTF8, 0, (WCHAR*)Stream_Pointer(irp->input), PathLength / 2,
-	                            &path, 0, NULL, NULL);
+	ptr = (WCHAR*)Stream_Pointer(irp->input);
+	if (!Stream_SafeSeek(irp->input, PathLength))
+		return ERROR_INVALID_DATA;
+	status = ConvertFromUnicode(CP_UTF8, 0, ptr, PathLength / 2, &path, 0, NULL, NULL);
 
 	if (status < 1)
 		if (!(path = (char*)calloc(1, 1)))
```
