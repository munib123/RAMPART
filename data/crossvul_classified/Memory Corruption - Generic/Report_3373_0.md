# CrossVul Fix Pair: Out-of-bounds Write in python
**Pair ID:** 3373_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3373_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```python
Lines 19-55 of the vulnerable file.

    s = s.rstrip()

    r = re.sub(REG_LINE_GPERF, '', s)
    if r != s: return r
    r = re.sub(REG_HASH_FUNC, 'hash(OnigCodePoint codes[])', s)
    if r != s: return r
    r = re.sub(REG_STR_AT, 'onig_codes_byte_at(codes, \\1)', s)
    if r != s: return r
    r = re.sub(REG_UNFOLD_KEY, 'unicode_unfold_key(OnigCodePoint code)', s)
    if r != s: return r
    r = re.sub(REG_ENTRY, '{\\1, \\2, \\3}', s)
    if r != s: return r
    r = re.sub(REG_EMPTY_ENTRY, '{0xffffffff, \\1, \\2}', s)
    if r != s: return r
    r = re.sub(REG_IF_LEN, 'if (0 == 0)', s)
    if r != s: return r
    r = re.sub(REG_GET_HASH, 'int key = hash(&code);', s)
    if r != s: return r
    r = re.sub(REG_GET_CODE, 'OnigCodePoint gcode = wordlist[key].code;', s)
    if r != s: return r
    r = re.sub(REG_CODE_CHECK, 'if (code == gcode)', s)
    if r != s: return r

    return s

def parse_file(f):
    print "/* This file was converted by gperf_unfold_key_conv.py\n      from gperf output file. */"

    line = f.readline()
    while line:
        s = parse_line(line)
        print s
        line = f.readline()


# main
parse_file(sys.stdin)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -36,7 +36,7 @@
     if r != s: return r
     r = re.sub(REG_GET_CODE, 'OnigCodePoint gcode = wordlist[key].code;', s)
     if r != s: return r
-    r = re.sub(REG_CODE_CHECK, 'if (code == gcode)', s)
+    r = re.sub(REG_CODE_CHECK, 'if (code == gcode && wordlist[key].index >= 0)', s)
     if r != s: return r
 
     return s
```
