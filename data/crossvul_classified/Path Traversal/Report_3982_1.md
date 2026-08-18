# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in json
**Pair ID:** 3982_1
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3982_1`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```json
Lines 1-23 of the vulnerable file.

{
  "appName": "Tiny File Manager",
  "version": "2.4.1",
  "language": [
    {
      "name": "فارسی",
      "code": "Fa",
      "translation": {
        "Tiny File Manager": "مدیریت فایل کوچک",
        "File Manager": "مدیریت فایل",
        "Sign in": "ورود",
        "Username": "نام کاربری",
        "Password": "گذرواژه",
        "Sign Out": "خروج",
        "Move": "جابجایی",
        "Copy": "کپی",
        "Save": "ذخیره",
        "Select all": "انتخاب همه",
        "Unselect all": "انتخاب نکردن همه",
        "File": "فایل",
        "Back": "برگشت",
        "Size": "حجم",
        "Perms": "دسترسی",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,6 @@
 {
   "appName": "Tiny File Manager",
-  "version": "2.4.1",
+  "version": "2.4.2",
   "language": [
     {
       "name": "فارسی",
```
