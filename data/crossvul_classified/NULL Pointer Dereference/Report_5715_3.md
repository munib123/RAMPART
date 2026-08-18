# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 5715_3
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5715_3`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 231-271 of the vulnerable file.

void sspi_SecureHandleInit(SecHandle* handle)
{
	if (!handle)
		return;

	memset(handle, 0xFF, sizeof(SecHandle));
}

void sspi_SecureHandleInvalidate(SecHandle* handle)
{
	if (!handle)
		return;

	sspi_SecureHandleInit(handle);
}

void* sspi_SecureHandleGetLowerPointer(SecHandle* handle)
{
	void* pointer;

	if (!handle)
		return NULL;

	pointer = (void*) ~((size_t) handle->dwLower);

	return pointer;
}

void sspi_SecureHandleSetLowerPointer(SecHandle* handle, void* pointer)
{
	if (!handle)
		return;

	handle->dwLower = (ULONG_PTR) (~((size_t) pointer));
}

void* sspi_SecureHandleGetUpperPointer(SecHandle* handle)
{
	void* pointer;

	if (!handle)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -248,7 +248,7 @@
 {
 	void* pointer;
 
-	if (!handle)
+	if (!handle || !SecIsValidHandle(handle))
 		return NULL;
 
 	pointer = (void*) ~((size_t) handle->dwLower);
@@ -268,7 +268,7 @@
 {
 	void* pointer;
 
-	if (!handle)
+	if (!handle || !SecIsValidHandle(handle))
 		return NULL;
 
 	pointer = (void*) ~((size_t) handle->dwUpper);
@@ -839,7 +839,7 @@
 
 SECURITY_STATUS SEC_ENTRY DeleteSecurityContext(PCtxtHandle phContext)
 {
-	char* Name;
+	char* Name = NULL;
 	SECURITY_STATUS status;
 	SecurityFunctionTableA* table;
 
```
