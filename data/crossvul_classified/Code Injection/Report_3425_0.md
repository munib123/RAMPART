# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in shell
**Pair ID:** 3425_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** shell
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3425_0`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```bash
Lines 14-56 of the vulnerable file.

#  echo "ERROR: lxc seems to work only on linux kernel 2.6.32 atm"
#  exit 1
#fi

# prepare unique FS layer
MOUNTDIR="$MOUNTDIR/$$"
mkdir -p "$MOUNTDIR" || exit 1

mount --bind "$FSDIR" "$MOUNTDIR" || exit 1

mkdir -p "$MOUNTDIR/$INNERSRCDIR" || exit 1
chown -R $RUNUSER "$MOUNTDIR/$INNERSRCDIR" .

# copy sources inside lxc root
#cp -a * "$MOUNTDIR/$INNERSRCDIR/" || exit 1
mount --bind "$PWD" "$MOUNTDIR/$INNERSRCDIR/"

echo "#!/bin/bash" > "$MOUNTDIR/$INNERSCRIPT"
echo "cd $INNERSRCDIR" >> "$MOUNTDIR/$INNERSCRIPT"

MODE=""
WITH_NET=""
COMMAND=""

while [ $# -gt 0 ]; do
  if [ "$1" == "--outdir" ] ; then
     shift
     OUTDIR="$1"
  else
     COMMAND="$COMMAND \"${1/\"/_}\" "
     if [ -z "$MODE" ]; then
        case "$1" in
          */download_url|*/tar_scm|*/download_src_package|*/update_source|*/download_files)
            WITH_NET="1"
            ;;
        esac
     fi
  fi
  shift
done

if [ -z "$OUTDIR" ] ; then
  echo "ERROR: no outdir given"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -31,23 +31,21 @@
 echo "#!/bin/bash" > "$MOUNTDIR/$INNERSCRIPT"
 echo "cd $INNERSRCDIR" >> "$MOUNTDIR/$INNERSCRIPT"
 
-MODE=""
-WITH_NET=""
-COMMAND=""
+WITH_NET="0"
+COMMAND="$1"
+shift
+case "$COMMAND" in
+  */download_url|*/tar_scm|*/download_src_package|*/update_source|*/download_files)
+    WITH_NET="1"
+    ;;
+esac
 
 while [ $# -gt 0 ]; do
   if [ "$1" == "--outdir" ] ; then
      shift
      OUTDIR="$1"
   else
-     COMMAND="$COMMAND \"${1/\"/_}\" "
-     if [ -z "$MODE" ]; then
-        case "$1" in
-          */download_url|*/tar_scm|*/download_src_package|*/update_source|*/download_files)
-            WITH_NET="1"
-            ;;
-        esac
-     fi
+     COMMAND="$COMMAND '${1//\'/_}'"
   fi
   shift
 done
@@ -63,12 +61,13 @@
 #if [ "$WITH_NET" == "1" ] ; then
 #  echo "rcnscd start" >> "$MOUNTDIR/$INNERSCRIPT"
 #fi
-echo -n "su $RUNUSER -c '" >> "$MOUNTDIR/$INNERSCRIPT"
-echo "$COMMAND --outdir $INNEROUTDIR'" >> "$MOUNTDIR/$INNERSCRIPT"
-chmod 0755 "$MOUNTDIR/$INNERSCRIPT"
+echo -n "su $RUNUSER -s ${INNERSCRIPT}.command" >> "$MOUNTDIR/$INNERSCRIPT"
+echo "#!/bin/bash"               >  "$MOUNTDIR/${INNERSCRIPT}.command"
+echo "${COMMAND[@]} --outdir $OUTDIR" >> "$MOUNTDIR/${INNERSCRIPT}.command"
+chmod 0755 "$MOUNTDIR/$INNERSCRIPT" "$MOUNTDIR/${INNERSCRIPT}.command"
 
 # construct jail
-LXC_CONF="/tmp/obs.service.$$"
+LXC_CONF="/obs.service.$$"
 echo "lxc.utsname = obs.service.$$" > $LXC_CONF
 if [ "$WITH_NET" == "1" ] ; then
   mount -t proc proc $MOUNTDIR/proc
```
