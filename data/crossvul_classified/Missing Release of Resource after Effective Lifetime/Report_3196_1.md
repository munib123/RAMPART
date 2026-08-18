# CrossVul Fix Pair: Missing Release of Resource after Effective Lifetime in cpp
**Pair ID:** 3196_1
**Vulnerability Class:** Missing Release of Resource after Effective Lifetime
**CWE:** CWE-772
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3196_1`)

## Vulnerability Information & PoC

## Description
Missing Release of Resource after Effective Lifetime - When a resource is not released after use, it can allow attackers to cause a denial of service by causing the allocation of resources without triggering their release.

## Vulnerable Code
```cpp
Lines 835-875 of the vulnerable file.

  // Just return if there is no reported error
  if (exception_->severity == UndefinedException)
    return;

  std::string message=formatExceptionMessage(exception_);
  nestedException=(Exception *) NULL;
  LockSemaphoreInfo(exception_->semaphore);
  if (exception_->exceptions != (void *) NULL)
    {
      index=GetNumberOfElementsInLinkedList((LinkedListInfo *)
        exception_->exceptions);
      while(index > 0)
      {
        p=(const ExceptionInfo *) GetValueFromLinkedList((LinkedListInfo *)
          exception_->exceptions,--index);
        if ((p->severity != exception_->severity) || (LocaleCompare(p->reason,
            exception_->reason) != 0) || (LocaleCompare(p->description,
            exception_->description) != 0))
          {
            if (nestedException == (Exception *) NULL)
              nestedException=createException(p);
            else
              {
                q=createException(p);
                nestedException->nested(q);
                nestedException=q;
              }
          }
      }
    }
  severity=exception_->severity;
  UnlockSemaphoreInfo(exception_->semaphore);

  if ((quiet_) && (severity < MagickCore::ErrorException))
    {
      delete nestedException;
      return;
    }

  DestroyExceptionInfo(exception_);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -852,12 +852,18 @@
             exception_->description) != 0))
           {
             if (nestedException == (Exception *) NULL)
-              nestedException=createException(p);
+              {
+                nestedException=createException(p);
+                q=nestedException;
+              }
             else
               {
-                q=createException(p);
-                nestedException->nested(q);
-                nestedException=q;
+                Exception
+                  *r;
+
+                r=createException(p);
+                q->nested(r);
+                q=r;
               }
           }
       }
```
