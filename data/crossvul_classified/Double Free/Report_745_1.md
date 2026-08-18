# CrossVul Fix Pair: Double Free in go
**Pair ID:** 745_1
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `745_1`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```go
Lines 92-132 of the vulnerable file.


		return "", "", errors.New(goMsg)
	}

	user := C.GoStringN(username, C.int(usernameLen))
	pass := C.GoStringN(secret, C.int(secretLen))
	return user, pass, nil
}

// List returns the stored URLs and corresponding usernames.
func (h Osxkeychain) List() (map[string]string, error) {
	credsLabelC := C.CString(credentials.CredsLabel)
	defer C.free(unsafe.Pointer(credsLabelC))

	var pathsC **C.char
	defer C.free(unsafe.Pointer(pathsC))
	var acctsC **C.char
	defer C.free(unsafe.Pointer(acctsC))
	var listLenC C.uint
	errMsg := C.keychain_list(credsLabelC, &pathsC, &acctsC, &listLenC)
	if errMsg != nil {
		defer C.free(unsafe.Pointer(errMsg))
		goMsg := C.GoString(errMsg)
		if goMsg == errCredentialsNotFound {
			return make(map[string]string), nil
		}

		return nil, errors.New(goMsg)
	}

	defer C.freeListData(&pathsC, listLenC)
	defer C.freeListData(&acctsC, listLenC)

	var listLen int
	listLen = int(listLenC)
	pathTmp := (*[1 << 30]*C.char)(unsafe.Pointer(pathsC))[:listLen:listLen]
	acctTmp := (*[1 << 30]*C.char)(unsafe.Pointer(acctsC))[:listLen:listLen]
	//taking the array of c strings into go while ignoring all the stuff irrelevant to credentials-helper
	resp := make(map[string]string)
	for i := 0; i < listLen; i++ {
		if C.GoString(pathTmp[i]) == "0" {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -109,6 +109,8 @@
 	defer C.free(unsafe.Pointer(acctsC))
 	var listLenC C.uint
 	errMsg := C.keychain_list(credsLabelC, &pathsC, &acctsC, &listLenC)
+	defer C.freeListData(&pathsC, listLenC)
+	defer C.freeListData(&acctsC, listLenC)
 	if errMsg != nil {
 		defer C.free(unsafe.Pointer(errMsg))
 		goMsg := C.GoString(errMsg)
@@ -118,9 +120,6 @@
 
 		return nil, errors.New(goMsg)
 	}
-
-	defer C.freeListData(&pathsC, listLenC)
-	defer C.freeListData(&acctsC, listLenC)
 
 	var listLen int
 	listLen = int(listLenC)
```
