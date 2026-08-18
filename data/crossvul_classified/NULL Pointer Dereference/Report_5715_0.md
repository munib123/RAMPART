# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 5715_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5715_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 1228-1268 of the vulnerable file.


	credssp = (rdpCredssp*) malloc(sizeof(rdpCredssp));
	ZeroMemory(credssp, sizeof(rdpCredssp));

	if (credssp != NULL)
	{
		HKEY hKey;
		LONG status;
		DWORD dwType;
		DWORD dwSize;

		credssp->instance = instance;
		credssp->settings = settings;
		credssp->server = settings->ServerMode;
		credssp->transport = transport;
		credssp->send_seq_num = 0;
		credssp->recv_seq_num = 0;
		ZeroMemory(&credssp->negoToken, sizeof(SecBuffer));
		ZeroMemory(&credssp->pubKeyAuth, sizeof(SecBuffer));
		ZeroMemory(&credssp->authInfo, sizeof(SecBuffer));

		if (credssp->server)
		{
			status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("Software\\FreeRDP\\Server"),
					0, KEY_READ | KEY_WOW64_64KEY, &hKey);

			if (status == ERROR_SUCCESS)
			{
				status = RegQueryValueEx(hKey, _T("SspiModule"), NULL, &dwType, NULL, &dwSize);

				if (status == ERROR_SUCCESS)
				{
					credssp->SspiModule = (LPTSTR) malloc(dwSize + sizeof(TCHAR));

					status = RegQueryValueEx(hKey, _T("SspiModule"), NULL, &dwType,
							(BYTE*) credssp->SspiModule, &dwSize);

					if (status == ERROR_SUCCESS)
					{
						_tprintf(_T("Using SSPI Module: %s\n"), credssp->SspiModule);
						RegCloseKey(hKey);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1245,6 +1245,7 @@
 		ZeroMemory(&credssp->negoToken, sizeof(SecBuffer));
 		ZeroMemory(&credssp->pubKeyAuth, sizeof(SecBuffer));
 		ZeroMemory(&credssp->authInfo, sizeof(SecBuffer));
+		SecInvalidateHandle(&credssp->context);
 
 		if (credssp->server)
 		{
```
