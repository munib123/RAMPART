# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 715_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `715_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1885-1925 of the vulnerable file.

			else
			{
#if 0
				Dump ("Open test on file %ls failed NTSTATUS 0x%08x\n", opentest->wszFileName, ntStatus);
#endif
			}

			Irp->IoStatus.Information = NT_SUCCESS (ntStatus) ? sizeof (OPEN_TEST_STRUCT) : 0;
			Irp->IoStatus.Status = ntStatus;
		}
		break;

	case TC_IOCTL_GET_SYSTEM_DRIVE_CONFIG:
		{
			GetSystemDriveConfigurationRequest *request = (GetSystemDriveConfigurationRequest *) Irp->AssociatedIrp.SystemBuffer;
			OBJECT_ATTRIBUTES ObjectAttributes;
			HANDLE NtFileHandle;
			UNICODE_STRING FullFileName;
			IO_STATUS_BLOCK IoStatus;
			LARGE_INTEGER offset;
			byte readBuffer [TC_SECTOR_SIZE_BIOS];

			if (!ValidateIOBufferSize (Irp, sizeof (GetSystemDriveConfigurationRequest), ValidateInputOutput))
				break;

			EnsureNullTerminatedString (request->DevicePath, sizeof (request->DevicePath));
			RtlInitUnicodeString (&FullFileName, request->DevicePath);

			InitializeObjectAttributes (&ObjectAttributes, &FullFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

			ntStatus = ZwCreateFile (&NtFileHandle,
				SYNCHRONIZE | GENERIC_READ, &ObjectAttributes, &IoStatus, NULL,
				FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_RANDOM_ACCESS, NULL, 0);

			if (NT_SUCCESS (ntStatus))
			{
				// Determine if the first sector contains a portion of the VeraCrypt Boot Loader
				offset.QuadPart = 0;	// MBR

				ntStatus = ZwReadFile (NtFileHandle,
					NULL,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1902,10 +1902,23 @@
 			UNICODE_STRING FullFileName;
 			IO_STATUS_BLOCK IoStatus;
 			LARGE_INTEGER offset;
-			byte readBuffer [TC_SECTOR_SIZE_BIOS];
+			size_t devicePathLen = 0;
 
 			if (!ValidateIOBufferSize (Irp, sizeof (GetSystemDriveConfigurationRequest), ValidateInputOutput))
 				break;
+
+			// check that request->DevicePath has the expected format "\\Device\\HarddiskXXX\\Partition0"
+			if (	!NT_SUCCESS (RtlUnalignedStringCchLengthW (request->DevicePath, TC_MAX_PATH, &devicePathLen))
+				||	(devicePathLen < 28) // 28 is the length of "\\Device\\Harddisk0\\Partition0" which is the minimum
+				||	(devicePathLen > 30) // 30 is the length of "\\Device\\Harddisk255\\Partition0" which is the maximum
+				||	(memcmp (request->DevicePath, L"\\Device\\Harddisk", 16 * sizeof (WCHAR)))
+				||	(memcmp (&request->DevicePath[devicePathLen - 11], L"\\Partition0", 11 * sizeof (WCHAR)))
+				)
+			{
+				Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
+				Irp->IoStatus.Information = 0;
+				break;
+			}
 
 			EnsureNullTerminatedString (request->DevicePath, sizeof (request->DevicePath));
 			RtlInitUnicodeString (&FullFileName, request->DevicePath);
@@ -1918,68 +1931,88 @@
 
 			if (NT_SUCCESS (ntStatus))
 			{
-				// Determine if the first sector contains a portion of the VeraCrypt Boot Loader
-				offset.QuadPart = 0;	// MBR
-
-				ntStatus = ZwReadFile (NtFileHandle,
-					NULL,
-					NULL,
-					NULL,
-					&IoStatus,
-					readBuffer,
-					sizeof(readBuffer),
-					&offset,
-					NULL);
-
-				if (NT_SUCCESS (ntStatus))
+				byte *readBuffer = TCalloc (TC_MAX_VOLUME_SECTOR_SIZE);
+				if (!readBuffer)
 				{
-					size_t i;
-
-					// Check for dynamic drive
-					request->DriveIsDynamic = FALSE;
-
-					if (readBuffer[510] == 0x55 && readBuffer[511] == 0xaa)
-					{
-						int i;
-						for (i = 0; i < 4; ++i)
-						{
-							if (readBuffer[446 + i * 16 + 4] == PARTITION_LDM)
-							{
-								request->DriveIsDynamic = TRUE;
-								break;
-							}
-						}
-					}
-
-					request->BootLoaderVersion = 0;
-					request->Configuration = 0;
-					request->UserConfiguration = 0;
-					request->CustomUserMessage[0] = 0;
-
-					// Search for the string "VeraCrypt"
-					for (i = 0; i < sizeof (readBuffer) - strlen (TC_APP_NAME); ++i)
-					{
-						if (memcmp (readBuffer + i, TC_APP_NAME, strlen (TC_APP_NAME)) == 0)
-						{
-							request->BootLoaderVersion = BE16 (*(uint16 *) (readBuffer + TC_BOOT_SECTOR_VERSION_OFFSET));
-							request->Configuration = readBuffer[TC_BOOT_SECTOR_CONFIG_OFFSET];
-
-							if (request->BootLoaderVersion != 0 && request->BootLoaderVersion <= VERSION_NUM)
-							{
-								request->UserConfiguration = readBuffer[TC_BOOT_SECTOR_USER_CONFIG_OFFSET];
-								memcpy (request->CustomUserMessage, readBuffer + TC_BOOT_SECTOR_USER_MESSAGE_OFFSET, TC_BOOT_SECTOR_USER_MESSAGE_MAX_LENGTH);
-							}
-							break;
-						}
-					}
-
-					Irp->IoStatus.Status = STATUS_SUCCESS;
-					Irp->IoStatus.Information = sizeof (*request);
+					Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
+					Irp->IoStatus.Information = 0;
 				}
 				else
 				{
-					Irp->IoStatus.Status = ntStatus;
-					Irp->IoStatus.Information = 0;
+					// Determine if the first sector contains a portion of the VeraCrypt Boot Loader
+					offset.QuadPart = 0;	// MBR
+
+					ntStatus = ZwReadFile (NtFileHandle,
+						NULL,
+						NULL,
+						NULL,
+						&IoStatus,
+						readBuffer,
+						TC_MAX_VOLUME_SECTOR_SIZE,
+						&offset,
+						NULL);
+
+					if (NT_SUCCESS (ntStatus))
+					{
+						// check that we could read all needed data
+						if (IoStatus.Information >= TC_SECTOR_SIZE_BIOS)
+						{
+							size_t i;
+
+							// Check for dynamic drive
+							request->DriveIsDynamic = FALSE;
+
+							if (readBuffer[510] == 0x55 && readBuffer[511] == 0xaa)
+							{
+								int i;
+								for (i = 0; i < 4; ++i)
+								{
+									if (readBuffer[446 + i * 16 + 4] == PARTITION_LDM)
+									{
+										request->DriveIsDynamic = TRUE;
+										break;
+									}
+								}
+							}
+
+							request->BootLoaderVersion = 0;
+							request->Configuration = 0;
+							request->UserConfiguration = 0;
+							request->CustomUserMessage[0] = 0;
+
+							// Search for the string "VeraCrypt"
+							for (i = 0; i < sizeof (readBuffer) - strlen (TC_APP_NAME); ++i)
+							{
+								if (memcmp (readBuffer + i, TC_APP_NAME, strlen (TC_APP_NAME)) == 0)
+								{
+									request->BootLoaderVersion = BE16 (*(uint16 *) (readBuffer + TC_BOOT_SECTOR_VERSION_OFFSET));
+									request->Configuration = readBuffer[TC_BOOT_SECTOR_CONFIG_OFFSET];
+
+									if (request->BootLoaderVersion != 0 && request->BootLoaderVersion <= VERSION_NUM)
+									{
+										request->UserConfiguration = readBuffer[TC_BOOT_SECTOR_USER_CONFIG_OFFSET];
+										memcpy (request->CustomUserMessage, readBuffer + TC_BOOT_SECTOR_USER_MESSAGE_OFFSET, TC_BOOT_SECTOR_USER_MESSAGE_MAX_LENGTH);
+									}
+									break;
+								}
+							}
+
+							Irp->IoStatus.Status = STATUS_SUCCESS;
+							Irp->IoStatus.Information = sizeof (*request);
+						}
+						else
+						{
+							Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
+							Irp->IoStatus.Information = 0;
+						}
+					}
+					else
+					{
+						Irp->IoStatus.Status = ntStatus;
+						Irp->IoStatus.Information = 0;
+					}
+
+					TCfree (readBuffer);
 				}
 
 				ZwClose (NtFileHandle);
```
