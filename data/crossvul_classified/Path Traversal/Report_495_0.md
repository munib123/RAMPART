# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in python
**Pair ID:** 495_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `495_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```python
Lines 2-42 of the vulnerable file.


##############################################################################
#                        2011 E2OpenPlugins                                  #
#                                                                            #
#  This file is open source software; you can redistribute it and/or modify  #
#     it under the terms of the GNU General Public License version 2 as      #
#               published by the Free Software Foundation.                   #
#                                                                            #
##############################################################################

import os
import re
import glob
from urllib import quote
import json

from twisted.web import static, resource, http

from Components.config import config
from Tools.Directories import fileExists

def new_getRequestHostname(self):
	host = self.getHeader(b'host')
	if host:
		if host[0]=='[':
			return host.split(']',1)[0] + "]"
		return host.split(':', 1)[0].encode('ascii')
	return self.getHost().host.encode('ascii')

http.Request.getRequestHostname = new_getRequestHostname


class FileController(resource.Resource):
	def render(self, request):
		action = "download"
		if "action" in request.args:
			action = request.args["action"][0]

		if "file" in request.args:
			filename = request.args["file"][0].decode('utf-8', 'ignore').encode('utf-8')
			filename = re.sub("^/+", "/", os.path.realpath(filename))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -19,6 +19,8 @@
 
 from Components.config import config
 from Tools.Directories import fileExists
+from utilities import lenient_force_utf_8, sanitise_filename_slashes
+
 
 def new_getRequestHostname(self):
 	host = self.getHeader(b'host')
@@ -38,8 +40,8 @@
 			action = request.args["action"][0]
 
 		if "file" in request.args:
-			filename = request.args["file"][0].decode('utf-8', 'ignore').encode('utf-8')
-			filename = re.sub("^/+", "/", os.path.realpath(filename))
+			filename = lenient_force_utf_8(request.args["file"][0])
+			filename = sanitise_filename_slashes(os.path.realpath(filename))
 
 			if not os.path.exists(filename):
 				return "File '%s' not found" % (filename)
```
