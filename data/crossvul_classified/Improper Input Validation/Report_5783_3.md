# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 5783_3
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5783_3`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 15-55 of the vulnerable file.

 * 1. Tag new release in the local git repository (for example, "git tag 2.5.1")
 * 2. Set the $version and $release variables for the new version.
 * 3. Run from CLI as: 'php build.php" from build directory.
 * 4. Check the archives in the tmp directory.
 *
 * @package		Joomla.Build
 * @copyright	Copyright (C) 2005 - 2013 Open Source Matters, Inc. All rights reserved.
 * @license		GNU General Public License version 2 or later; see LICENSE.txt

 */

// Make sure file and folder permissions are set correctly
umask(022);

// Set version for each build
// Version is first 2 digits (like '1.7', '2.5', or '3.0')
$version = '3.1';

// Set release for each build
// Release is third digit (like '0', '1', or '2')
$release = '2';

// Set path to git binary (e.g., /usr/local/git/bin/git or /urs/bin/git)
$gitPath = '/usr/bin/git';

// Path to local git repository (parent folder of build folder)
$repo = dirname(dirname(__FILE__));
$here = dirname(__FILE__);

// Build packages in tmp folder
$tmp = $here . '/tmp';

$fullpath = $here . '/tmp/' . $version . '.' . $release;
$full = $version . '.' . $release;

echo "Start build for version $full.\n";
echo "Delete old release folder.\n";
system('rm -rf ' . $tmp);
mkdir($tmp);
mkdir($fullpath);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,7 +32,7 @@
 
 // Set release for each build
 // Release is third digit (like '0', '1', or '2')
-$release = '2';
+$release = '5';
 
 // Set path to git binary (e.g., /usr/local/git/bin/git or /urs/bin/git)
 $gitPath = '/usr/bin/git';
@@ -75,6 +75,7 @@
 // Note: If we add new top-level directories or files, be sure to include them here.
 $filesArray = array(
 		"administrator/index.php\n" => true,
+		"bin/index.html\n" => true,
 		"cache/index.html\n" => true,
 		"cli/index.html\n" => true,
 		"components/index.html\n" => true,
@@ -114,8 +115,9 @@
 	// Loop through and add all files except: tests, installation, build, .git, or docs
 	foreach ($files AS $file)
 	{
-		if (substr($file, 2, 5) != 'tests' && substr($file, 2, 12) != 'installation' && substr($file,2,5) != 'build'
-		&& substr($file, 2, 4) != '.git' && substr($file, 2, 4) != 'docs' )
+		if (substr($file, 2, 5) != 'tests' && substr($file, 2, 12) != 'installation' && substr($file, 2, 5) != 'build'
+		&& substr($file, 2, 4) != '.git' && substr($file, 2, 4) != 'docs' && substr($file, 2, 7) != '.travis'
+		&& substr($file, 2, 6) != 'travis' && substr($file, 2, 7) != 'phpunit' && substr($file, -3) != '.md')
 		{
 			// Don't add deleted files to the list
 			if (substr($file, 0, 1) != 'D')
```
