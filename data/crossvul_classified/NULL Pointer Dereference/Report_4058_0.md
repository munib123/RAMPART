# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 4058_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4058_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 34-77 of the vulnerable file.

sraSpanCreate(int start, int end, const sraSpanList *subspan) {
  sraSpan *item = (sraSpan*)malloc(sizeof(sraSpan));
  if (!item) return NULL;
  item->_next = item->_prev = NULL;
  item->start = start;
  item->end = end;
  item->subspan = sraSpanListDup(subspan);
  return item;
}

static sraSpan *
sraSpanDup(const sraSpan *src) {
  sraSpan *span;
  if (!src) return NULL;
  span = sraSpanCreate(src->start, src->end, src->subspan);
  return span;
}

static void
sraSpanInsertAfter(sraSpan *newspan, sraSpan *after) {
  newspan->_next = after->_next;
  newspan->_prev = after;
  after->_next->_prev = newspan;
  after->_next = newspan;
}

static void
sraSpanInsertBefore(sraSpan *newspan, sraSpan *before) {
  newspan->_next = before;
  newspan->_prev = before->_prev;
  before->_prev->_next = newspan;
  before->_prev = newspan;
}

static void
sraSpanRemove(sraSpan *span) {
  span->_prev->_next = span->_next;
  span->_next->_prev = span->_prev;
}

static void
sraSpanDestroy(sraSpan *span) {
  if (span->subspan) sraSpanListDestroy(span->subspan);
  free(span);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -51,24 +51,30 @@
 
 static void
 sraSpanInsertAfter(sraSpan *newspan, sraSpan *after) {
-  newspan->_next = after->_next;
-  newspan->_prev = after;
-  after->_next->_prev = newspan;
-  after->_next = newspan;
+  if(newspan && after) {
+    newspan->_next = after->_next;
+    newspan->_prev = after;
+    after->_next->_prev = newspan;
+    after->_next = newspan;
+  }
 }
 
 static void
 sraSpanInsertBefore(sraSpan *newspan, sraSpan *before) {
-  newspan->_next = before;
-  newspan->_prev = before->_prev;
-  before->_prev->_next = newspan;
-  before->_prev = newspan;
+  if(newspan && before) {
+    newspan->_next = before;
+    newspan->_prev = before->_prev;
+    before->_prev->_next = newspan;
+    before->_prev = newspan;
+  }
 }
 
 static void
 sraSpanRemove(sraSpan *span) {
-  span->_prev->_next = span->_next;
-  span->_next->_prev = span->_prev;
+  if(span) {
+    span->_prev->_next = span->_next;
+    span->_next->_prev = span->_prev;
+  }
 }
 
 static void
```
