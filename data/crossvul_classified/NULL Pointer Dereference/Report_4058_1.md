# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 4058_1
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4058_1`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 190-230 of the vulnerable file.

}

rfbClientPtr
rfbClientIteratorHead(rfbClientIteratorPtr i)
{
#if defined(LIBVNCSERVER_HAVE_LIBPTHREAD) || defined(LIBVNCSERVER_HAVE_WIN32THREADS)
  if(i->next != 0) {
    rfbDecrClientRef(i->next);
    rfbIncrClientRef(i->screen->clientHead);
  }
#endif
  LOCK(rfbClientListMutex);
  i->next = i->screen->clientHead;
  UNLOCK(rfbClientListMutex);
  return i->next;
}

rfbClientPtr
rfbClientIteratorNext(rfbClientIteratorPtr i)
{
  if(i->next == 0) {
    LOCK(rfbClientListMutex);
    i->next = i->screen->clientHead;
    UNLOCK(rfbClientListMutex);
  } else {
    rfbClientPtr cl = i->next;
    i->next = i->next->next;
    rfbDecrClientRef(cl);
  }

#if defined(LIBVNCSERVER_HAVE_LIBPTHREAD) || defined(LIBVNCSERVER_HAVE_WIN32THREADS)
    if(!i->closedToo)
      while(i->next && i->next->sock<0)
        i->next = i->next->next;
    if(i->next)
      rfbIncrClientRef(i->next);
#endif

    return i->next;
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -207,6 +207,8 @@
 rfbClientPtr
 rfbClientIteratorNext(rfbClientIteratorPtr i)
 {
+  if (!i)
+    return NULL;
   if(i->next == 0) {
     LOCK(rfbClientListMutex);
     i->next = i->screen->clientHead;
@@ -231,7 +233,7 @@
 void
 rfbReleaseClientIterator(rfbClientIteratorPtr iterator)
 {
-  if(iterator->next) rfbDecrClientRef(iterator->next);
+  if(iterator && iterator->next) rfbDecrClientRef(iterator->next);
   free(iterator);
 }
 
```
