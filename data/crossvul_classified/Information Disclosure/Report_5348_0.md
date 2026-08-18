# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in shell
**Pair ID:** 5348_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** shell
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5348_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```bash
Lines 1683-1723 of the vulnerable file.


    if [[ "$(cpio --help)" == *--reproducible* ]]; then
        CPIO_REPRODUCIBLE=1
    else
        dinfo "cpio does not support '--reproducible'. Resulting image will not be reproducible."
    fi
fi

[[ "$UID" != 0 ]] && cpio_owner_root="-R 0:0"

if [[ $create_early_cpio = yes ]]; then
    echo 1 > "$early_cpio_dir/d/early_cpio"

    if [[ $DRACUT_REPRODUCIBLE ]]; then
        find "$early_cpio_dir/d" -newer "$dracutbasedir/dracut-functions.sh" -print0 \
            | xargs -r -0 touch -h -m -c -r "$dracutbasedir/dracut-functions.sh"
    fi

    # The microcode blob is _before_ the initramfs blob, not after
    if ! (
            cd "$early_cpio_dir/d"
            find . -print0 | sort -z \
                | cpio ${CPIO_REPRODUCIBLE:+--reproducible} --null $cpio_owner_root -H newc -o --quiet > "${DRACUT_TMPDIR}/initramfs.img"
        ); then
        dfatal "dracut: creation of $outfile failed"
        exit 1
    fi
fi

if ! (
        umask 077; cd "$initdir"
        find . -print0 | sort -z \
            | cpio ${CPIO_REPRODUCIBLE:+--reproducible} --null $cpio_owner_root -H newc -o --quiet \
            | $compress >> "${DRACUT_TMPDIR}/initramfs.img"
    ); then
    dfatal "dracut: creation of $outfile failed"
    exit 1
fi

if (( maxloglvl >= 5 )); then
    if [[ $allowlocal ]]; then
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1700,7 +1700,7 @@
 
     # The microcode blob is _before_ the initramfs blob, not after
     if ! (
-            cd "$early_cpio_dir/d"
+            umask 077; cd "$early_cpio_dir/d"
             find . -print0 | sort -z \
                 | cpio ${CPIO_REPRODUCIBLE:+--reproducible} --null $cpio_owner_root -H newc -o --quiet > "${DRACUT_TMPDIR}/initramfs.img"
         ); then
```
