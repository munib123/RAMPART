# CrossVul Fix Pair: Improper Input Validation in cpp
**Pair ID:** 512_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `512_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```cpp
Lines 2344-2384 of the vulnerable file.

            FTerminal->FatalError(NULL, FMTLOAD(SCP_INVALID_CONTROL_RECORD, (Ctrl, Line)));
        }

        TFileMasks::TParams MaskParams;
        MaskParams.Modification = FileData.Modification;

        // We reach this point only if control record was 'C' or 'D'
        try
        {
          FileData.RemoteRights.Octal = CutToChar(Line, L' ', True);
          // do not trim leading spaces of the filename
          __int64 TSize = StrToInt64(CutToChar(Line, L' ', False).TrimRight());
          MaskParams.Size = TSize;
          // Security fix: ensure the file ends up where we asked for it.
          // (accept only filename, not path)
          UnicodeString OnlyFileName = UnixExtractFileName(Line);
          if (Line != OnlyFileName)
          {
            FTerminal->LogEvent(FORMAT(L"Warning: Remote host set a compound pathname '%s'", (Line)));
          }

          FullFileName = SourceDir + OnlyFileName;
          OperationProgress->SetFile(FullFileName);
          OperationProgress->SetTransferSize(TSize);
        }
        catch (Exception &E)
        {
          {
            TSuspendFileOperationProgress Suspend(OperationProgress);
            FTerminal->Log->AddException(&E);
          }
          SCPError(LoadStr(SCP_ILLEGAL_FILE_DESCRIPTOR), false);
        }

        // last possibility to cancel transfer before it starts
        if (OperationProgress->Cancel)
        {
          throw ESkipFile(NULL, MainInstructions(LoadStr(USER_TERMINATED)));
        }

        bool Dir = (Ctrl == L'D');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2361,6 +2361,10 @@
           {
             FTerminal->LogEvent(FORMAT(L"Warning: Remote host set a compound pathname '%s'", (Line)));
           }
+          if ((Level == 0) && (OnlyFileName != UnixExtractFileName(FileName)))
+          {
+            SCPError(LoadStr(UNREQUESTED_FILE), False);
+          }
 
           FullFileName = SourceDir + OnlyFileName;
           OperationProgress->SetFile(FullFileName);
```
