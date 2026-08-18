# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2516_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2516_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-24 of the vulnerable file.

<?php

// $Id: info.php 591 2009-03-01 19:42:05Z BerndJM $

/*

 Website Baker Project <http://www.websitebaker.org/>
 Copyright (C) 2004-2008, Ryan Djurovich

 Website Baker is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 2 of the License, or
 (at your option) any later version.

 Website Baker is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with Website Baker; if not, write to the Free Software
 Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 -----------------------------------------------------------------------------------------
  v0.41 (marmot; 25.05.2013)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,26 +1,18 @@
 <?php
-
-// $Id: info.php 591 2009-03-01 19:42:05Z BerndJM $
-
 /*
-
- Website Baker Project <http://www.websitebaker.org/>
- Copyright (C) 2004-2008, Ryan Djurovich
-
- Website Baker is free software; you can redistribute it and/or modify
- it under the terms of the GNU General Public License as published by
- the Free Software Foundation; either version 2 of the License, or
- (at your option) any later version.
-
- Website Baker is distributed in the hope that it will be useful,
- but WITHOUT ANY WARRANTY; without even the implied warranty of
- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
- GNU General Public License for more details.
-
- You should have received a copy of the GNU General Public License
- along with Website Baker; if not, write to the Free Software
- Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
- -----------------------------------------------------------------------------------------
+  *
+ * WBCE CMS
+ * Way Better Content Editing.
+ * Visit http://wbce.org to learn more and to join the community.
+ *
+ * @copyright Ryan Djurovich (2004-2009)
+ * @copyright WebsiteBaker Org. e.V. (2009-2015)
+ * @copyright WBCE Project (2015-)
+ * @license GNU GPL2 (or any later version)
+ 
+  v0.50 (florian; 08.05.2017)
+  !fix XSS vulnerability (reported by strukt93@gmail.com)
+ 
   v0.41 (marmot; 25.05.2013)
   ! admin url is now set by config.php
   ! notice regarding mktime
@@ -65,7 +57,7 @@
 $module_directory = 'user_search';
 $module_name = 'User search';
 $module_function = 'tool';
-$module_version = '0.41';
+$module_version = '0.50';
 $module_platform = '2.8.3';
 $module_author = 'Bernd Michna';
 $module_license = 'GNU General Public License';
```
