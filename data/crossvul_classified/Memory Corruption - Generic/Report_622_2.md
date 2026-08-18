# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 622_2
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `622_2`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 33-73 of the vulnerable file.

 *          void        gplotDestroy()
 *          l_int32     gplotAddPlot()
 *          l_int32     gplotSetScaling()
 *          l_int32     gplotMakeOutput()
 *          l_int32     gplotGenCommandFile()
 *          l_int32     gplotGenDataFiles()
 *
 *     Quick and dirty plots
 *          l_int32     gplotSimple1()
 *          l_int32     gplotSimple2()
 *          l_int32     gplotSimpleN()
 *          l_int32     gplotSimpleXY1()
 *          l_int32     gplotSimpleXY2()
 *          l_int32     gplotSimpleXYN()
 *
 *     Serialize for I/O
 *          GPLOT      *gplotRead()
 *          l_int32     gplotWrite()
 *
 *
 *     Utility for programmatic plotting using gnuplot 7.3.2 or later
 *     Enabled:
 *         ~ output to png (color), ps (mono), x11 (color), latex (mono)
 *         ~ optional title for graph
 *         ~ optional x and y axis labels
 *         ~ multiple plots on one frame
 *         ~ optional title for each plot on the frame
 *         ~ optional log scaling on either or both axes
 *         ~ choice of 5 plot styles for each plot
 *         ~ choice of 2 plot modes, either using one input array
 *           (Y vs index) or two input arrays (Y vs X).  This
 *           choice is made implicitly depending on the number of
 *           input arrays.
 *
 *     Usage:
 *         gplotCreate() initializes for plotting
 *         gplotAddPlot() for each plot on the frame
 *         gplotMakeOutput() to generate all output files and run gnuplot
 *         gplotDestroy() to clean up
 *
 *     Example of use:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -50,9 +50,9 @@
  *          l_int32     gplotWrite()
  *
  *
- *     Utility for programmatic plotting using gnuplot 7.3.2 or later
+ *     Utility for programmatic plotting using gnuplot 4.6 or later
  *     Enabled:
- *         ~ output to png (color), ps (mono), x11 (color), latex (mono)
+ *         ~ output to png (color), ps and eps (mono), latex (mono)
  *         ~ optional title for graph
  *         ~ optional x and y axis labels
  *         ~ multiple plots on one frame
@@ -100,7 +100,7 @@
 #include <string.h>
 #include "allheaders.h"
 
-static const l_int32  L_BUF_SIZE = 512;
+static const l_int32  L_BUFSIZE = 512;  /* hardcoded below in fscanf */
 
 const char  *gplotstylenames[] = {"with lines",
                                   "with points",
@@ -142,7 +142,7 @@
             const char  *ylabel)
 {
 char    *newroot;
-char     buf[L_BUF_SIZE];
+char     buf[L_BUFSIZE];
 l_int32  badchar;
 GPLOT   *gplot;
 
@@ -169,16 +169,16 @@
     newroot = genPathname(rootname, NULL);
     gplot->rootname = newroot;
     gplot->outformat = outformat;
-    snprintf(buf, L_BUF_SIZE, "%s.cmd", rootname);
+    snprintf(buf, L_BUFSIZE, "%s.cmd", rootname);
     gplot->cmdname = stringNew(buf);
     if (outformat == GPLOT_PNG)
-        snprintf(buf, L_BUF_SIZE, "%s.png", newroot);
+        snprintf(buf, L_BUFSIZE, "%s.png", newroot);
     else if (outformat == GPLOT_PS)
-        snprintf(buf, L_BUF_SIZE, "%s.ps", newroot);
+        snprintf(buf, L_BUFSIZE, "%s.ps", newroot);
     else if (outformat == GPLOT_EPS)
-        snprintf(buf, L_BUF_SIZE, "%s.eps", newroot);
+        snprintf(buf, L_BUFSIZE, "%s.eps", newroot);
     else if (outformat == GPLOT_LATEX)
-        snprintf(buf, L_BUF_SIZE, "%s.tex", newroot);
+        snprintf(buf, L_BUFSIZE, "%s.tex", newroot);
     gplot->outname = stringNew(buf);
     if (title) gplot->title = stringNew(title);
     if (xlabel) gplot->xlabel = stringNew(xlabel);
@@ -266,7 +266,7 @@
              l_int32      plotstyle,
              const char  *plottitle)
 {
-char       buf[L_BUF_SIZE];
+char       buf[L_BUFSIZE];
 char       emptystring[] = "";
 char      *datastr, *title;
 l_int32    n, i;
@@ -303,7 +303,7 @@
 
         /* Generate and save data filename */
     gplot->nplots++;
-    snprintf(buf, L_BUF_SIZE, "%s.data.%d", gplot->rootname, gplot->nplots);
+    snprintf(buf, L_BUFSIZE, "%s.data.%d", gplot->rootname, gplot->nplots);
     sarrayAddString(gplot->datanames, buf, L_COPY);
 
         /* Generate data and save as a string */
@@ -314,7 +314,7 @@
         else
             valx = startx + i * delx;
         numaGetFValue(nay, i, &valy);
-        snprintf(buf, L_BUF_SIZE, "%f %f\n", valx, valy);
+        snprintf(buf, L_BUFSIZE, "%f %f\n", valx, valy);
         sarrayAddString(sa, buf, L_COPY);
     }
     datastr = sarrayToString(sa, 0);
@@ -378,7 +378,7 @@
 l_int32
 gplotMakeOutput(GPLOT  *gplot)
 {
-char     buf[L_BUF_SIZE];
+char     buf[L_BUFSIZE];
 char    *cmdname;
 l_int32  ignore;
 
@@ -392,9 +392,9 @@
     cmdname = genPathname(gplot->cmdname, NULL);
 
 #ifndef _WIN32
-    snprintf(buf, L_BUF_SIZE, "gnuplot %s", cmdname);
+    snprintf(buf, L_BUFSIZE, "gnuplot %s", cmdname);
 #else
-    snprintf(buf, L_BUF_SIZE, "wgnuplot %s", cmdname);
+    snprintf(buf, L_BUFSIZE, "wgnuplot %s", cmdname);
 #endif  /* _WIN32 */
 
 #ifndef OS_IOS /* iOS 11 does not support system() */
@@ -415,7 +415,7 @@
 l_int32
 gplotGenCommandFile(GPLOT  *gplot)
 {
-char     buf[L_BUF_SIZE];
+char     buf[L_BUFSIZE];
 char    *cmdstr, *plottitle, *dataname;
 l_int32  i, plotstyle, nplots;
 FILE    *fp;
@@ -430,43 +430,43 @@
 
         /* Generate command data instructions */
     if (gplot->title) {   /* set title */
-        snprintf(buf, L_BUF_SIZE, "set title '%s'", gplot->title);
+        snprintf(buf, L_BUFSIZE, "set title '%s'", gplot->title);
         sarrayAddString(gplot->cmddata, buf, L_COPY);
     }
     if (gplot->xlabel) {   /* set xlabel */
-        snprintf(buf, L_BUF_SIZE, "set xlabel '%s'", gplot->xlabel);
+        snprintf(buf, L_BUFSIZE, "set xlabel '%s'", gplot->xlabel);
         sarrayAddString(gplot->cmddata, buf, L_COPY);
     }
     if (gplot->ylabel) {   /* set ylabel */
-        snprintf(buf, L_BUF_SIZE, "set ylabel '%s'", gplot->ylabel);
+        snprintf(buf, L_BUFSIZE, "set ylabel '%s'", gplot->ylabel);
         sarrayAddString(gplot->cmddata, buf, L_COPY);
     }
 
         /* Set terminal type and output */
     if (gplot->outformat == GPLOT_PNG) {
-        snprintf(buf, L_BUF_SIZE, "set terminal png; set output '%s'",
+        snprintf(buf, L_BUFSIZE, "set terminal png; set output '%s'",
                  gplot->outname);
     } else if (gplot->outformat == GPLOT_PS) {
-        snprintf(buf, L_BUF_SIZE, "set terminal postscript; set output '%s'",
+        snprintf(buf, L_BUFSIZE, "set terminal postscript; set output '%s'",
                  gplot->outname);
     } else if (gplot->outformat == GPLOT_EPS) {
-        snprintf(buf, L_BUF_SIZE,
+        snprintf(buf, L_BUFSIZE,
                  "set terminal postscript eps; set output '%s'",
                  gplot->outname);
     } else if (gplot->outformat == GPLOT_LATEX) {
-        snprintf(buf, L_BUF_SIZE, "set terminal latex; set output '%s'",
+        snprintf(buf, L_BUFSIZE, "set terminal latex; set output '%s'",
                  gplot->outname);
     }
     sarrayAddString(gplot->cmddata, buf, L_COPY);
 
     if (gplot->scaling == GPLOT_LOG_SCALE_X ||
         gplot->scaling == GPLOT_LOG_SCALE_X_Y) {
-        snprintf(buf, L_BUF_SIZE, "set logscale x");
+        snprintf(buf, L_BUFSIZE, "set logscale x");
         sarrayAddString(gplot->cmddata, buf, L_COPY);
     }
     if (gplot->scaling == GPLOT_LOG_SCALE_Y ||
         gplot->scaling == GPLOT_LOG_SCALE_X_Y) {
-        snprintf(buf, L_BUF_SIZE, "set logscale y");
+        snprintf(buf, L_BUFSIZE, "set logscale y");
         sarrayAddString(gplot->cmddata, buf, L_COPY);
     }
 
@@ -476,17 +476,17 @@
         dataname = sarrayGetString(gplot->datanames, i, L_NOCOPY);
         numaGetIValue(gplot->plotstyles, i, &plotstyle);
         if (nplots == 1) {
-            snprintf(buf, L_BUF_SIZE, "plot '%s' title '%s' %s",
+            snprintf(buf, L_BUFSIZE, "plot '%s' title '%s' %s",
                      dataname, plottitle, gplotstylenames[plotstyle]);
         } else {
             if (i == 0)
-                snprintf(buf, L_BUF_SIZE, "plot '%s' title '%s' %s, \\",
+                snprintf(buf, L_BUFSIZE, "plot '%s' title '%s' %s, \\",
                      dataname, plottitle, gplotstylenames[plotstyle]);
             else if (i < nplots - 1)
-                snprintf(buf, L_BUF_SIZE, " '%s' title '%s' %s, \\",
+                snprintf(buf, L_BUFSIZE, " '%s' title '%s' %s, \\",
                      dataname, plottitle, gplotstylenames[plotstyle]);
             else
-                snprintf(buf, L_BUF_SIZE, " '%s' title '%s' %s",
+                snprintf(buf, L_BUFSIZE, " '%s' title '%s' %s",
                      dataname, plottitle, gplotstylenames[plotstyle]);
         }
         sarrayAddString(gplot->cmddata, buf, L_COPY);
@@ -820,7 +820,7 @@
 GPLOT *
 gplotRead(const char  *filename)
 {
-char     buf[L_BUF_SIZE];
+char     buf[L_BUFSIZE];
 char    *rootname, *title, *xlabel, *ylabel, *ignores;
 l_int32  outformat, ret, version, ignore;
 FILE    *fp;
@@ -844,16 +844,16 @@
         return (GPLOT *)ERROR_PTR("invalid gplot version", procName, NULL);
     }
 
-    ignore = fscanf(fp, "Rootname: %s\n", buf);
+    ignore = fscanf(fp, "Rootname: %511s\n", buf);  /* L_BUFSIZE - 1 */
     rootname = stringNew(buf);
     ignore = fscanf(fp, "Output format: %d\n", &outformat);
-    ignores = fgets(buf, L_BUF_SIZE, fp);   /* Title: ... */
+    ignores = fgets(buf, L_BUFSIZE, fp);   /* Title: ... */
     title = stringNew(buf + 7);
     title[strlen(title) - 1] = '\0';
-    ignores = fgets(buf, L_BUF_SIZE, fp);   /* X axis label: ... */
... (diff truncated)
```
