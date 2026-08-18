# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 1720_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1720_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 24-64 of the vulnerable file.

    'Directory Creation Mode:' => 'Directory Creation Mode:',
    'Directory is not writable! File has not been saved!' => 'Directory is not writable! File has not been saved!',
    'Do you want to display hidden files on unix systems? <br/> If you select no, all files starting with "." will not be displayed.' => 'Do you want to display hidden files on unix systems? <br/> If you select no, all files starting with "." will not be displayed.',
    'Do you want to show backup files? If you select no, all files ending with "~" will not be displayed.' => 'Do you want to show backup files? If you select no, all files ending with "~" will not be displayed.',
    'File' => 'File',
    'File :name has been created with success!' => 'File :name has been created with success!',
    'File :name has not been created!' => 'File :name has not been created!',
    'File Creation Defaults' => 'File Creation Defaults',
    'File Creation Mode:' => 'File Creation Mode:',
    'File Manager' => 'File Manager',
    'File Manager Settings' => 'File Manager Settings',
    'File has been saved with success!' => 'File has been saved with success!',
    'File has not been uploaded!' => 'File has not been uploaded!',
    'File is not writable! File has not been saved!' => 'File is not writable! File has not been saved!',
    'File or directory not found!' => 'File or directory not found!',
    'Files' => 'Files',
    'General settings' => 'General settings',
    'Modified' => 'Modified',
    'Modify' => 'Modify',
    'No' => 'No',
    'Permission denied!' => 'Permission denied!',
    'Permissions' => 'Permissions',
    'Provides interface to manage files from the administration.' => 'Provides interface to manage files from the administration.',
    'Rename' => 'Rename',
    'Save' => 'Save',
    'Save and Continue Editing' => 'Save and Continue Editing',
    'Show backup files' => 'Show backup files',
    'Show hidden files' => 'Show hidden files',
    'Size' => 'Size',
    'Umask:' => 'Umask:',
    'Upload' => 'Upload',
    'Upload file' => 'Upload file',
    'Yes' => 'Yes',
    'You do not have permission to access the requested page!' => 'You do not have permission to access the requested page!',
    'You do not have sufficient permissions to change the permissions on a file or directory.' => 'You do not have sufficient permissions to change the permissions on a file or directory.',
    'You do not have sufficient permissions to create a directory.' => 'You do not have sufficient permissions to create a directory.',
    'You do not have sufficient permissions to create a file.' => 'You do not have sufficient permissions to create a file.',
    'You do not have sufficient permissions to delete a file or directory.' => 'You do not have sufficient permissions to delete a file or directory.',
    'You do not have sufficient permissions to rename this file or directory.' => 'You do not have sufficient permissions to rename this file or directory.',
    'You do not have sufficient permissions to upload a file.' => 'You do not have sufficient permissions to upload a file.',
    'delete file icon' => 'delete file icon',
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -41,6 +41,8 @@
     'Modified' => 'Modified',
     'Modify' => 'Modify',
     'No' => 'No',
+    'Not allowed to upload files with extension :ext' => 'Not allowed to upload files with extension :ext',
+    'Not allowed to rename to :ext' => 'Not allowed to rename to :ext',
     'Permission denied!' => 'Permission denied!',
     'Permissions' => 'Permissions',
     'Provides interface to manage files from the administration.' => 'Provides interface to manage files from the administration.',
```
