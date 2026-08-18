# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in cpp
**Pair ID:** 2514_0
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2514_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```cpp
Lines 366-425 of the vulnerable file.

   Perror((char *)msg,size);
   if (level > -1) NetSendError((ERootdErrors)level);
   RootdClose();
   exit(1);
}
////////////////////////////////////////////////////////////////////////////////

void ErrSys(int level,const char *msg, int size)
{
   Perror((char *)msg,size);
   ErrFatal(level,msg,size);
}

//--- Rootd routines -----------------------------------------------------------

const char *shellMeta   = "~*[]{}?$";
const char *shellStuff  = "(){}<>\"'";
const char  shellEscape = '\\';

////////////////////////////////////////////////////////////////////////////////
/// Escape specchars in src with escchar and copy to dst.

static int EscChar(const char *src, char *dst, int dstlen, const char *specchars, char escchar)
{
   const char *p;
   char *q, *end = dst+dstlen-1;

   for (p = src, q = dst; *p && q < end; ) {
      if (strchr(specchars, *p)) {
         *q++ = escchar;
         if (q < end)
            *q++ = *p++;
      } else
         *q++ = *p++;
   }
   *q = '\0';

   if (*p != 0)
      return -1;
   return q-dst;
}

////////////////////////////////////////////////////////////////////////////////
/// After SO_KEEPALIVE times out we probably get a SIGPIPE.

void SigPipe(int)
{
   ErrorInfo("SigPipe: rootd.cxx: got a SIGPIPE");

   // Terminate properly
   RpdAuthCleanup(0, 0);
   RootdClose();
   exit(1);
}

////////////////////////////////////////////////////////////////////////////////
/// Returns the user's home directory.

static const char *HomeDirectory(const char *name)
{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -383,29 +383,6 @@
 const char  shellEscape = '\\';
 
 ////////////////////////////////////////////////////////////////////////////////
-/// Escape specchars in src with escchar and copy to dst.
-
-static int EscChar(const char *src, char *dst, int dstlen, const char *specchars, char escchar)
-{
-   const char *p;
-   char *q, *end = dst+dstlen-1;
-
-   for (p = src, q = dst; *p && q < end; ) {
-      if (strchr(specchars, *p)) {
-         *q++ = escchar;
-         if (q < end)
-            *q++ = *p++;
-      } else
-         *q++ = *p++;
-   }
-   *q = '\0';
-
-   if (*p != 0)
-      return -1;
-   return q-dst;
-}
-
-////////////////////////////////////////////////////////////////////////////////
 /// After SO_KEEPALIVE times out we probably get a SIGPIPE.
 
 void SigPipe(int)
@@ -447,6 +424,166 @@
 }
 
 ////////////////////////////////////////////////////////////////////////////////
+/// Returns the current working directory.
+
+static const char *WorkingDirectory()
+{
+   static char path[kMAXPATHLEN];
+
+   if (getcwd(path, kMAXPATHLEN)) return path;
+   return 0;
+}
+
+////////////////////////////////////////////////////////////////////////////
+/// Method for pathname expansion.
+/// Returns kTRUE in case of error and kFALSE otherwise.
+
+Bool_t RootdExpandFileName(const char *fname, char *xname, const int kBufSize)
+{
+   int n, ier, iter, lx, ncopy;
+   char *inp, *out, *x, *t, buff[kBufSize * 4];
+   const char *b, *c, *e;
+   const char *p;
+
+   iter = 0;
+   xname[0] = 0;
+   inp = buff + kBufSize;
+   out = inp + kBufSize;
+   inp[-1] = ' ';
+   inp[0] = 0;
+   out[-1] = ' ';
+   c = fname + strspn(fname, " \t\f\r");
+   // VP  if (isalnum(c[0])) { strcpy(inp, WorkingDirectory()); strcat(inp, "/"); } // add $cwd
+
+   strncat(inp, c, kBufSize - strlen(inp) - 1);
+
+again:
+   iter++;
+   c = inp;
+   ier = 0;
+   x = out;
+   x[0] = 0;
+
+   p = 0;
+   e = 0;
+   if (c[0] == '~' && c[1] == '/') { // ~/ case
+      std::string hd = HomeDirectory(0);
+      p = hd.c_str();
+      e = c + 1;
+      if (p) { // we have smth to copy
+         strlcpy(x, p, kBufSize);
+         x += strlen(p);
+         c = e;
+      } else {
+         ++ier;
+         ++c;
+      }
+   } else if (c[0] == '~' && c[1] != '/') { // ~user case
+      n = strcspn(c + 1, "/ ");
+      buff[0] = 0;
+      strncat(buff, c + 1, n);
+      std::string hd = HomeDirectory(buff);
+      e = c + 1 + n;
+      if (!hd.empty()) { // we have smth to copy
+         p = hd.c_str();
+         strlcpy(x, p, kBufSize);
+         x += strlen(p);
+         c = e;
+      } else {
+         x++ [0] = c[0];
+         //++ier;
+         ++c;
+      }
+   }
+
+   for (; c[0]; c++) {
+
+      p = 0;
+      e = 0;
+
+      if (c[0] == '.' && c[1] == '/' && c[-1] == ' ') { // $cwd
+         std::string wd = WorkingDirectory();
+         strlcpy(buff, wd.c_str(), kBufSize);
+         p = buff;
+         e = c + 1;
+      }
+      if (p) { // we have smth to copy */
+         strlcpy(x, p, kBufSize);
+         x += strlen(p);
+         c = e - 1;
+         continue;
+      }
+
+      if (c[0] != '$') { // not $, simple copy
+         x++ [0] = c[0];
+      } else { // we have a $
+         b = c + 1;
+         if (c[1] == '(') b++;
+         if (c[1] == '{') b++;
+         if (b[0] == '$')
+            e = b + 1;
+         else
+            for (e = b; isalnum(e[0]) || e[0] == '_'; e++)
+               ;
+         buff[0] = 0;
+         strncat(buff, b, e - b);
+         p = getenv(buff);
+         if (!p) { // too bad, try UPPER case
+            for (t = buff; (t[0] = toupper(t[0])); t++)
+               ;
+            p = getenv(buff);
+         }
+         if (!p) { // too bad, try Lower case
+            for (t = buff; (t[0] = tolower(t[0])); t++)
+               ;
+            p = getenv(buff);
+         }
+         if (!p && !strcmp(buff, "cwd")) { // it is $cwd
+            std::string wd = WorkingDirectory();
+            strlcpy(buff, wd.c_str(), kBufSize);
+            p = buff;
+         }
+         if (!p && !strcmp(buff, "$")) { // it is $$ (replace by getpid())
+            snprintf(buff, kBufSize * 4, "%d", (int)getpid());
+            p = buff;
+         }
+         if (!p) { // too bad, nothing can help
+            ier++;
+            x++ [0] = c[0];
+         } else { // It is OK, copy result
+            int lp = strlen(p);
+            if (lp >= kBufSize) {
+               // make sure lx will be >= kBufSize (see below)
+               strlcpy(x, p, kBufSize);
+               x += kBufSize;
+               break;
+            }
+            strcpy(x, p);
+            x += lp;
+            c = (b == c + 1) ? e - 1 : e;
+         }
+      }
+   }
+
+   x[0] = 0;
+   lx = x - out;
+   if (ier && iter < 3) {
+      strlcpy(inp, out, kBufSize);
+      goto again;
+   }
+   ncopy = (lx >= kBufSize) ? kBufSize - 1 : lx;
+   xname[0] = 0;
+   strncat(xname, out, ncopy);
+
+   if (ier || ncopy != lx) {
+      Error(ErrFatal, kErrFatal, "RootdExpandFileName: fatal error:\n\t input: %s\n\t output: %s", fname, xname);
+      return true;
+   }
+
+   return false;
+}
+
+////////////////////////////////////////////////////////////////////////////////
 /// Expand a pathname getting rid of special shell characters like ~.$, etc.
 /// Returned string must be freed by caller.
 
@@ -455,88 +592,28 @@
    const char *patbuf = name;
 
    // skip leading blanks
-   while (*patbuf == ' ')
-      patbuf++;
+   while (*patbuf == ' ') patbuf++;
 
    // any shell meta characters?
+   bool needesc = false;
    for (const char *p = patbuf; *p; p++)
-      if (strchr(shellMeta, *p))
-         goto needshell;
-
+      if (strchr(shellMeta, *p)) {
+         needesc = true;
+         break;
+      }
+
+   // Escape meta characters, if required
+   if (needesc) {
+      const int kBufSize = kMAXPATHLEN;
+      char xname[kBufSize];
+      if (RootdExpandFileName(name, xname, kBufSize)) {
+         Error(ErrFatal, kErrFatal, "RootdExpandPathName: problem escaping meta characters");
+         return 0;
+      } else {
+         return strdup(xname);
+      }
+   }
    return strdup(name);
-
-needshell:
-   // escape shell quote characters
-   char escPatbuf[kMAXPATHLEN];
-   EscChar(patbuf, escPatbuf, sizeof(escPatbuf), shellStuff, shellEscape);
-
-   char cmd[kMAXPATHLEN];
-#ifdef __hpux
-   strlcpy(cmd, "/bin/echo ", sizeof(cmd));
-#else
-   strlcpy(cmd, "echo ", sizeof(cmd));
-#endif
-
-   // emulate csh -> popen executes sh
-   if (escPatbuf[0] == '~') {
-      const char *hd;
-      if (escPatbuf[1] != '\0' && escPatbuf[1] != '/') {
-         // extract user name
-         char uname[70], *p, *q;
-         for (p = &escPatbuf[1], q = uname; *p && *p !='/';)
-            *q++ = *p++;
-         *q = '\0';
-         hd = HomeDirectory(uname);
-         if (hd == 0)
-            strcat(cmd, escPatbuf);
-         else {
-            strcat(cmd, hd);
-            strcat(cmd, p);
-         }
-
-      } else {
-         hd = HomeDirectory(0);
-         if (hd == 0) {
-            Error(ErrSys, kErrFatal, "RootdExpandPathName: no home directory");
-            return 0;
-         }
-         strcat(cmd, hd);
-         strcat(cmd, &escPatbuf[1]);
-      }
-   } else
-      strcat(cmd, escPatbuf);
-
-   FILE *pf;
-   if ((pf = ::popen(&cmd[0], "r")) == 0) {
-      Error(ErrSys, kErrFatal, "RootdExpandPathName: error in popen(%s)", cmd);
-      return 0;
-   }
-
-   // read first argument
-   char expPatbuf[kMAXPATHLEN];
-   int  ch, i, cnt = 0;
-again:
-   for (i = 0, ch = fgetc(pf); ch != EOF && ch != ' ' && ch != '\n'; i++, ch = fgetc(pf)) {
-      expPatbuf[i] = ch;
-      cnt++;
-   }
-   // this will be true if forked process was not yet ready to be read
-   if (cnt == 0 && ch == EOF) goto again;
-   expPatbuf[cnt] = '\0';
-
-   // skip rest of pipe
-   while (ch != EOF) {
-      ch = fgetc(pf);
-      if (ch == ' ' || ch == '\t') {
-         ::pclose(pf);
... (diff truncated)
```
