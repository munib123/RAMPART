# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 3614_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3614_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 1-25 of the vulnerable file.

<?php
/* Copyright (C) 2003-2004 Rodolphe Quiedeville  <rodolphe@quiedeville.org>
 * Copyright (C) 2004-2010 Laurent Destailleur   <eldy@users.sourceforge.net>
 * Copyright (C) 2005      Marc Barilley / Ocebo <marc@ocebo.com>
 * Copyright (C) 2005-2009 Regis Houssin         <regis@dolibarr.fr>
 * Copyright (C) 2005      Simon TOSSER          <simon@kornog-computing.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/**
 *       \file       htdocs/comm/action/document.php
 *       \ingroup    agenda
 *       \brief      Page of documents linked to actions
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,7 +2,7 @@
 /* Copyright (C) 2003-2004 Rodolphe Quiedeville  <rodolphe@quiedeville.org>
  * Copyright (C) 2004-2010 Laurent Destailleur   <eldy@users.sourceforge.net>
  * Copyright (C) 2005      Marc Barilley / Ocebo <marc@ocebo.com>
- * Copyright (C) 2005-2009 Regis Houssin         <regis@dolibarr.fr>
+ * Copyright (C) 2005-2012 Regis Houssin         <regis@dolibarr.fr>
  * Copyright (C) 2005      Simon TOSSER          <simon@kornog-computing.com>
  *
  * This program is free software; you can redistribute it and/or modify
```
