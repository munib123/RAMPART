# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in c
**Pair ID:** 5843_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5843_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```c
Lines 3195-3235 of the vulnerable file.

  }
  snprintf(dest, destsize,"(%s >= date_trunc('%s',%s) and %s < date_trunc('%s',%s) + interval '1 %s')",
           timecol, minTimeInterval, minTimeStamp,
           timecol, maxTimeInterval, maxTimeStamp, maxTimeInterval);
  return MS_SUCCESS;
}

int msPostGISLayerSetTimeFilter(layerObj *lp, const char *timestring, const char *timefield)
{
  char **atimes, **aranges = NULL;
  int numtimes=0,i=0,numranges=0;
  size_t buffer_size = 512;
  char buffer[512], bufferTmp[512];

  buffer[0] = '\0';
  bufferTmp[0] = '\0';

  if (!lp || !timestring || !timefield)
    return MS_FALSE;

  /* discrete time */
  if (strstr(timestring, ",") == NULL &&
      strstr(timestring, "/") == NULL) { /* discrete time */
    createPostgresTimeCompareSimple(timefield, timestring, buffer, buffer_size);
  } else {

    /* multiple times, or ranges */
    atimes = msStringSplit (timestring, ',', &numtimes);
    if (atimes == NULL || numtimes < 1)
      return MS_FALSE;

    strlcat(buffer, "(", buffer_size);
    for(i=0; i<numtimes; i++) {
      if(i!=0) {
        strlcat(buffer, " OR ", buffer_size);
      }
      strlcat(buffer, "(", buffer_size);
      aranges = msStringSplit(atimes[i],  '/', &numranges);
      if(!aranges) return MS_FALSE;
      if(numranges == 1) {
        /* we don't have range, just a simple time */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3212,6 +3212,11 @@
   if (!lp || !timestring || !timefield)
     return MS_FALSE;
 
+  if( strchr(timestring,'\'') || strchr(timestring, '\\') ) {
+     msSetError(MS_MISCERR, "Invalid time filter.", "msPostGISLayerSetTimeFilter()");
+     return MS_FALSE;
+  }
+
   /* discrete time */
   if (strstr(timestring, ",") == NULL &&
       strstr(timestring, "/") == NULL) { /* discrete time */
```
