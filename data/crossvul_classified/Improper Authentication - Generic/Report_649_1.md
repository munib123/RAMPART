# CrossVul Fix Pair: Improper Authentication in python
**Pair ID:** 649_1
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `649_1`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```python
Lines 1-21 of the vulnerable file.

# Copyright (c) 2013-2017 by Ron Frederick <ronf@timeheart.net>.
# All rights reserved.
#
# This program and the accompanying materials are made available under
# the terms of the Eclipse Public License v1.0 which accompanies this
# distribution and is available at:
#
#     http://www.eclipse.org/legal/epl-v10.html
#
# Contributors:
#     Ron Frederick - initial implementation, API, and documentation

"""AsyncSSH version information"""

__author__ = 'Ron Frederick'

__author_email__ = 'ronf@timeheart.net'

__url__ = 'http://asyncssh.timeheart.net'

__version__ = '1.12.0'
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -18,4 +18,4 @@
 
 __url__ = 'http://asyncssh.timeheart.net'
 
-__version__ = '1.12.0'
+__version__ = '1.12.1'
```
