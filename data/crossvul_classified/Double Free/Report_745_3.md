# CrossVul Fix Pair: Double Free in go
**Pair ID:** 745_3
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `745_3`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```go
Lines 75-115 of the vulnerable file.

	}
	user := C.GoString(username)
	pass := C.GoString(secret)
	if pass == "" {
		return "", "", credentials.NewErrCredentialsNotFound()
	}
	return user, pass, nil
}

// List returns the stored URLs and corresponding usernames for a given credentials label
func (h Secretservice) List() (map[string]string, error) {
	credsLabelC := C.CString(credentials.CredsLabel)
	defer C.free(unsafe.Pointer(credsLabelC))

	var pathsC **C.char
	defer C.free(unsafe.Pointer(pathsC))
	var acctsC **C.char
	defer C.free(unsafe.Pointer(acctsC))
	var listLenC C.uint
	err := C.list(credsLabelC, &pathsC, &acctsC, &listLenC)
	if err != nil {
		defer C.g_error_free(err)
		return nil, errors.New("Error from list function in secretservice_linux.c likely due to error in secretservice library")
	}
	defer C.freeListData(&pathsC, listLenC)
	defer C.freeListData(&acctsC, listLenC)

	resp := make(map[string]string)

	listLen := int(listLenC)
	if listLen == 0 {
		return resp, nil
	}
	// The maximum capacity of the following two slices is limited to (2^29)-1 to remain compatible
	// with 32-bit platforms. The size of a `*C.char` (a pointer) is 4 Byte on a 32-bit system
	// and (2^29)*4 == math.MaxInt32 + 1. -- See issue golang/go#13656
	pathTmp := (*[(1 << 29) - 1]*C.char)(unsafe.Pointer(pathsC))[:listLen:listLen]
	acctTmp := (*[(1 << 29) - 1]*C.char)(unsafe.Pointer(acctsC))[:listLen:listLen]
	for i := 0; i < listLen; i++ {
		resp[C.GoString(pathTmp[i])] = C.GoString(acctTmp[i])
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -92,12 +92,12 @@
 	defer C.free(unsafe.Pointer(acctsC))
 	var listLenC C.uint
 	err := C.list(credsLabelC, &pathsC, &acctsC, &listLenC)
+	defer C.freeListData(&pathsC, listLenC)
+	defer C.freeListData(&acctsC, listLenC)
 	if err != nil {
 		defer C.g_error_free(err)
 		return nil, errors.New("Error from list function in secretservice_linux.c likely due to error in secretservice library")
 	}
-	defer C.freeListData(&pathsC, listLenC)
-	defer C.freeListData(&acctsC, listLenC)
 
 	resp := make(map[string]string)
 
```
