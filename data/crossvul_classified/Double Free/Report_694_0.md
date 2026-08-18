# CrossVul Fix Pair: Double Free in c
**Pair ID:** 694_0
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `694_0`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 436-476 of the vulnerable file.

            }
            goto out;
        }
    }

    /* all options passed */
    ret = TRUE;

out:
    if (argv)
    {
        LocalFree(argv);
    }
    return ret;
}

static BOOL
GetStartupData(HANDLE pipe, STARTUP_DATA *sud)
{
    size_t size, len;
    BOOL ret = FALSE;
    WCHAR *data = NULL;
    DWORD bytes, read;

    bytes = PeekNamedPipeAsync(pipe, 1, &exit_event);
    if (bytes == 0)
    {
        MsgToEventLog(M_SYSERR, TEXT("PeekNamedPipeAsync failed"));
        ReturnLastError(pipe, L"PeekNamedPipeAsync");
        goto out;
    }

    size = bytes / sizeof(*data);
    if (size == 0)
    {
        MsgToEventLog(M_SYSERR, TEXT("malformed startup data: 1 byte received"));
        ReturnError(pipe, ERROR_STARTUP_DATA, L"GetStartupData", 1, &exit_event);
        goto out;
    }

    data = malloc(bytes);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -453,7 +453,6 @@
 GetStartupData(HANDLE pipe, STARTUP_DATA *sud)
 {
     size_t size, len;
-    BOOL ret = FALSE;
     WCHAR *data = NULL;
     DWORD bytes, read;
 
@@ -462,7 +461,7 @@
     {
         MsgToEventLog(M_SYSERR, TEXT("PeekNamedPipeAsync failed"));
         ReturnLastError(pipe, L"PeekNamedPipeAsync");
-        goto out;
+        goto err;
     }
 
     size = bytes / sizeof(*data);
@@ -470,7 +469,7 @@
     {
         MsgToEventLog(M_SYSERR, TEXT("malformed startup data: 1 byte received"));
         ReturnError(pipe, ERROR_STARTUP_DATA, L"GetStartupData", 1, &exit_event);
-        goto out;
+        goto err;
     }
 
     data = malloc(bytes);
@@ -478,7 +477,7 @@
     {
         MsgToEventLog(M_SYSERR, TEXT("malloc failed"));
         ReturnLastError(pipe, L"malloc");
-        goto out;
+        goto err;
     }
 
     read = ReadPipeAsync(pipe, data, bytes, 1, &exit_event);
@@ -486,14 +485,14 @@
     {
         MsgToEventLog(M_SYSERR, TEXT("ReadPipeAsync failed"));
         ReturnLastError(pipe, L"ReadPipeAsync");
-        goto out;
+        goto err;
     }
 
     if (data[size - 1] != 0)
     {
         MsgToEventLog(M_ERR, TEXT("Startup data is not NULL terminated"));
         ReturnError(pipe, ERROR_STARTUP_DATA, L"GetStartupData", 1, &exit_event);
-        goto out;
+        goto err;
     }
 
     sud->directory = data;
@@ -503,7 +502,7 @@
     {
         MsgToEventLog(M_ERR, TEXT("Startup data ends at working directory"));
         ReturnError(pipe, ERROR_STARTUP_DATA, L"GetStartupData", 1, &exit_event);
-        goto out;
+        goto err;
     }
 
     sud->options = sud->directory + len;
@@ -513,16 +512,16 @@
     {
         MsgToEventLog(M_ERR, TEXT("Startup data ends at command line options"));
         ReturnError(pipe, ERROR_STARTUP_DATA, L"GetStartupData", 1, &exit_event);
-        goto out;
+        goto err;
     }
 
     sud->std_input = sud->options + len;
-    data = NULL; /* don't free data */
-    ret = TRUE;
-
-out:
+    return TRUE;
+
+err:
+    sud->directory = NULL;		/* caller must not free() */
     free(data);
-    return ret;
+    return FALSE;
 }
 
 
```
