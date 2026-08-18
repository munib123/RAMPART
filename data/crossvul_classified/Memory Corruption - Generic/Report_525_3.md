# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 525_3
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `525_3`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 629-669 of the vulnerable file.

	        || (!load->fileName && !load->isom && !(load->flags & GF_SM_LOAD_FOR_PLAYBACK) )
#endif
	   ) return GF_BAD_PARAM;

	if (!load->type) {
#ifndef GPAC_DISABLE_ISOM
		if (load->isom) {
			load->type = GF_SM_LOAD_MP4;
		} else
#endif
		{
			ext = (char *)strrchr(load->fileName, '.');
			if (!ext) return GF_NOT_SUPPORTED;
			if (!stricmp(ext, ".gz")) {
				char *anext;
				ext[0] = 0;
				anext = (char *)strrchr(load->fileName, '.');
				ext[0] = '.';
				ext = anext;
			}
			strcpy(szExt, &ext[1]);
			strlwr(szExt);
			if (strstr(szExt, "bt")) load->type = GF_SM_LOAD_BT;
			else if (strstr(szExt, "wrl")) load->type = GF_SM_LOAD_VRML;
			else if (strstr(szExt, "x3dv")) load->type = GF_SM_LOAD_X3DV;
#ifndef GPAC_DISABLE_LOADER_XMT
			else if (strstr(szExt, "xmt") || strstr(szExt, "xmta")) load->type = GF_SM_LOAD_XMTA;
			else if (strstr(szExt, "x3d")) load->type = GF_SM_LOAD_X3D;
#endif
			else if (strstr(szExt, "swf")) load->type = GF_SM_LOAD_SWF;
			else if (strstr(szExt, "mov")) load->type = GF_SM_LOAD_QT;
			else if (strstr(szExt, "svg")) load->type = GF_SM_LOAD_SVG;
			else if (strstr(szExt, "xsr")) load->type = GF_SM_LOAD_XSR;
			else if (strstr(szExt, "xbl")) load->type = GF_SM_LOAD_XBL;
			else if (strstr(szExt, "xml")) {
				char *rtype = gf_xml_get_root_type(load->fileName, &e);
				if (rtype) {
					if (!strcmp(rtype, "SAFSession")) load->type = GF_SM_LOAD_XSR;
					else if (!strcmp(rtype, "XMT-A")) load->type = GF_SM_LOAD_XMTA;
					else if (!strcmp(rtype, "X3D")) load->type = GF_SM_LOAD_X3D;
					else if (!strcmp(rtype, "bindings")) load->type = GF_SM_LOAD_XBL;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -646,6 +646,10 @@
 				ext[0] = '.';
 				ext = anext;
 			}
+			if (strlen(ext) < 2 || strlen(ext) > sizeof(szExt)) {
+				GF_LOG(GF_LOG_ERROR, GF_LOG_SCENE, ("[Scene Manager] invalid extension in file name %s\n", load->fileName));
+				return GF_NOT_SUPPORTED;
+			}
 			strcpy(szExt, &ext[1]);
 			strlwr(szExt);
 			if (strstr(szExt, "bt")) load->type = GF_SM_LOAD_BT;
```
