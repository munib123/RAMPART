# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 978_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `978_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 1-33 of the vulnerable file.

/*
   3APA3A simpliest proxy server
   (c) 2002-2008 by ZARAZA <3APA3A@security.nnov.ru>

   please read License Agreement

*/

#include "proxy.h"

#define RETURN(xxx) { param->res = xxx; goto CLEANRET; }

#define LINESIZE 2048

extern FILE *writable;
FILE * confopen();
extern void decodeurl(unsigned char *s, int filter);

struct printparam {
	char buf[1024];
	int inbuf;
	struct clientparam *cp;
};

static void stdpr(struct printparam* pp, char *buf, int inbuf){
	if((pp->inbuf + inbuf > 1024) || !buf) {
		socksend(pp->cp->clisock, (unsigned char *)pp->buf, pp->inbuf, conf.timeouts[STRING_S]);
		pp->inbuf = 0;
		if(!buf) return;
	}
	if(inbuf >= 1000){
		socksend(pp->cp->clisock, (unsigned char *)buf, inbuf, conf.timeouts[STRING_S]);		
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -10,7 +10,7 @@
 
 #define RETURN(xxx) { param->res = xxx; goto CLEANRET; }
 
-#define LINESIZE 2048
+#define LINESIZE 65536
 
 extern FILE *writable;
 FILE * confopen();
@@ -341,7 +341,7 @@
  char *sb;
  char *req = NULL;
  struct printparam pp;
- int contentlen = 0;
+ unsigned contentlen = 0;
  int isform = 0;
 
  pp.inbuf = 0;
@@ -390,7 +390,8 @@
 	else if(i > 15 && (!strncasecmp(buf, "content-length:", 15))){
 		sb = buf + 15;
 		while(isspace(*sb))sb++;
-		contentlen = atoi(sb);
+		sscanf(sb, "%u", &contentlen);
+		if(contentlen > LINESIZE*1024) contentlen = 0;
 	}
 	else if(i > 13 && (!strncasecmp(buf, "content-type:", 13))){
 		sb = buf + 13;
@@ -520,7 +521,7 @@
 				break;
 			}
 				printstr(&pp, "<h3>Please be careful editing config file remotely</h3>");
-				printstr(&pp, "<form method=\"POST\" action=\"/U\"><textarea cols=\"80\" rows=\"30\" name=\"conffile\">");
+				printstr(&pp, "<form method=\"POST\" action=\"/U\" enctype=\"application/x-www-form-urlencoded\"><textarea cols=\"80\" rows=\"30\" name=\"conffile\">");
 				while(fgets(buf, 256, fp)){
 					printstr(&pp, buf);
 				}
@@ -530,24 +531,23 @@
 		}
 	case 'U':
 		{
-			int l=0;
+			unsigned l=0;
 			int error = 0;
 
-			if(!writable || fseek(writable, 0, 0)){
+			if(!writable || !contentlen || fseek(writable, 0, 0)){
 				error = 1;
 			}
-			while((i = sockgetlinebuf(param, CLIENT, (unsigned char *)buf, LINESIZE - 1, '+', conf.timeouts[STRING_S])) > 0){
+			while(l < contentlen && (i = sockgetlinebuf(param, CLIENT, (unsigned char *)buf, (contentlen - l) > LINESIZE - 1?LINESIZE - 1:contentlen - l, '+', conf.timeouts[STRING_S])) > 0){
 				if(i > (contentlen - l)) i = (contentlen - l);
-				buf[i] = 0;
 				if(!l){
-					if(strncasecmp(buf, "conffile=", 9)) error = 1;
+					if(i<9 || strncasecmp(buf, "conffile=", 9)) error = 1;
 				}
 				if(!error){
+					buf[i] = 0;
 					decodeurl((unsigned char *)buf, 1);
 					fprintf(writable, "%s", l? buf : buf + 9);
 				}
 				l += i;
-				if(l >= contentlen) break;
 			}
 			if(writable && !error){
 				fflush(writable);
```
