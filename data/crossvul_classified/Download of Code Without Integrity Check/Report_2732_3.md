# CrossVul Fix Pair: Download of Code Without Integrity Check in c
**Pair ID:** 2732_3
**Vulnerability Class:** Download of Code Without Integrity Check
**CWE:** CWE-494
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2732_3`)

## Vulnerability Information & PoC

## Description
Download of Code Without Integrity Check - An attacker can execute malicious code by compromising the host server, performing DNS spoofing, or modifying the code in transit.

## Vulnerable Code
```c
Lines 1657-1697 of the vulnerable file.

		case IDCLOSE:
		case IDCANCEL:
			if (download_status != 1) {
				reset_localization(IDD_NEW_VERSION);
				safe_free(filepath);
				EndDialog(hDlg, LOWORD(wParam));
			}
			return (INT_PTR)TRUE;
		case IDC_WEBSITE:
			ShellExecuteA(hDlg, "open", RUFUS_URL, NULL, NULL, SW_SHOWNORMAL);
			break;
		case IDC_DOWNLOAD:	// Also doubles as abort and launch function
			switch(download_status) {
			case 1:		// Abort
				FormatStatus = ERROR_SEVERITY_ERROR|FAC(FACILITY_STORAGE)|ERROR_CANCELLED;
				download_status = 0;
				break;
			case 2:		// Launch newer version and close this one
				Sleep(1000);	// Add a delay on account of antivirus scanners

				if (ValidateSignature(hDlg, filepath) != NO_ERROR)
					break;

				memset(&si, 0, sizeof(si));
				memset(&pi, 0, sizeof(pi));
				si.cb = sizeof(si);
				if (!CreateProcessU(filepath, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
					PrintInfo(0, MSG_214);
					uprintf("Failed to launch new application: %s\n", WindowsErrorString());
				} else {
					PrintInfo(0, MSG_213);
					PostMessage(hDlg, WM_COMMAND, (WPARAM)IDCLOSE, 0);
					PostMessage(hMainDialog, WM_CLOSE, 0, 0);
				}
				break;
			default:	// Download
				if (update.download_url == NULL) {
					uprintf("Could not get download URL\n");
					break;
				}
				for (i=(int)strlen(update.download_url); (i>0)&&(update.download_url[i]!='/'); i--);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1674,8 +1674,12 @@
 			case 2:		// Launch newer version and close this one
 				Sleep(1000);	// Add a delay on account of antivirus scanners
 
-				if (ValidateSignature(hDlg, filepath) != NO_ERROR)
+				if (ValidateSignature(hDlg, filepath) != NO_ERROR) {
+					// Unconditionally delete the download and disable the "Launch" control
+					_unlinkU(filepath);
+					EnableWindow(GetDlgItem(hDlg, IDC_DOWNLOAD), FALSE);
 					break;
+				}
 
 				memset(&si, 0, sizeof(si));
 				memset(&pi, 0, sizeof(pi));
```
