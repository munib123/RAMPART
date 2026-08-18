# CrossVul Fix Pair: Allocation of Resources Without Limits or Throttling in c
**Pair ID:** 4064_0
**Vulnerability Class:** Allocation of Resources Without Limits or Throttling
**CWE:** CWE-770
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4064_0`)

## Vulnerability Information & PoC

## Description
Allocation of Resources Without Limits or Throttling - Code frequently has to work with limited resources, so programmers must be careful to ensure that resources are not consumed too quickly, or too easily.

## Vulnerable Code
```c
Lines 48-88 of the vulnerable file.

#endif

#ifndef _MSC_VER
/* Strings.h is not available in MSVC */
#include <strings.h>
#endif

#include <stdarg.h>
#include <time.h>

#include "crypto.h"

#include "sasl.h"
#ifdef LIBVNCSERVER_HAVE_LZO
#include <lzo/lzo1x.h>
#else
#include "minilzo.h"
#endif
#include "tls.h"


/*
 * rfbClientLog prints a time-stamped message to the log file (stderr).
 */

rfbBool rfbEnableClientLogging=TRUE;

static void
rfbDefaultClientLog(const char *format, ...)
{
    va_list args;
    char buf[256];
    time_t log_clock;

    if(!rfbEnableClientLogging)
      return;

    va_start(args, format);

    time(&log_clock);
    strftime(buf, 255, "%d/%m/%Y %X ", localtime(&log_clock));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -65,6 +65,7 @@
 #endif
 #include "tls.h"
 
+#define MAX_TEXTCHAT_SIZE 10485760 /* 10MB */
 
 /*
  * rfbClientLog prints a time-stamped message to the log file (stderr).
@@ -2159,6 +2160,8 @@
               client->HandleTextChat(client, (int)rfbTextChatFinished, NULL);
           break;
       default:
+	  if(msg.tc.length > MAX_TEXTCHAT_SIZE)
+	      return FALSE;
           buffer=malloc(msg.tc.length+1);
           if (!ReadFromRFBServer(client, buffer, msg.tc.length))
           {
```
