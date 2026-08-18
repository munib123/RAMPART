# CrossVul Fix Pair: Out-of-bounds Read in php
**Pair ID:** 1383_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1383_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```php
Lines 374-414 of the vulnerable file.


$text = "This is a Simple text.";
var_dump(strpbrk($text, "mi"));
var_dump(strpbrk($text, "S"));

var_dump(strpos("abcdef abcdef", "a"));
var_dump(strpos("abcdef abcdef", "a", 1));
var_dump(strpos("abcdef abcdef", "A", 1));
var_dump(strpos("abcdef abcdef", "", 0));

var_dump(stripos("abcdef abcdef", "A", 1));

var_dump(strrpos("abcdef abcdef", "a"));
var_dump(strrpos("0123456789a123456789b123456789c", "7", -5));
var_dump(strrpos("0123456789a123456789b123456789c", "7", 20));
var_dump(strrpos("0123456789a123456789b123456789c", "7", 28));


var_dump(strripos("abcdef abcdef", "A"));

$text = "This is a test";
var_dump(substr_count($text, "is"));
var_dump(substr_count($text, "is", 3));
var_dump(substr_count($text, "is", 3, 3));
var_dump(substr_count("gcdgcdgcd", "gcdgcd"));

var_dump(strspn("foo", "o", 1, 2));

var_dump(strcspn("foo", "o", 1, 2));

var_dump(strlen("test"));

$ret = count_chars("Two Ts and one F.");
var_dump($ret[ord("T")]);

var_dump(str_word_count("Two Ts and one F."));
var_dump(str_word_count("", 2));
var_dump(str_word_count("1", 2));
var_dump(str_word_count("1 2", 2));

var_dump(levenshtein("carrrot", "carrot"));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -390,6 +390,15 @@
 
 
 var_dump(strripos("abcdef abcdef", "A"));
+
+var_dump(strrpos("abc", "c\0", -1));
+var_dump(strripos("abc", "c\0", -1));
+var_dump(strrpos("abc", "abc", -3));
+var_dump(strripos("abc", "abc", -3));
+var_dump(strrpos("aaaa", "aa", -1));
+var_dump(strripos("aaaa", "aa", -1));
+var_dump(strrpos("aaaa", "aa", -2));
+var_dump(strripos("aaaa", "aa", -2));
 
 $text = "This is a test";
 var_dump(substr_count($text, "is"));
```
