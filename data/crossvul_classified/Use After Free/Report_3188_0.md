# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 3188_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3188_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 209-249 of the vulnerable file.

      if(!CLI_ISCONTAINED(exe, exesz, ucur, backsize) || !CLI_ISCONTAINED(exe, exesz, ucur-backbytes, backsize)) error=1;
      else while(backsize--) {
	*ucur=*(ucur-backbytes);
	ucur++;
      }
    }
    free(compd);
    if(error) {
      cli_dbgmsg("WWPack: decompression error\n");
      break;
    }
    if (error || !*structs++) break;
  }

  if(!error) {
    if (pe+6 > exesz || pe+7 > exesz || pe+0x28 > exesz ||
		pe+0x50 > exesz || pe+0x14 > exesz) 
	return CL_EFORMAT;
    exe[pe+6]=(uint8_t)scount;
    exe[pe+7]=(uint8_t)(scount>>8);
    cli_writeint32(&exe[pe+0x28], cli_readint32(wwsect+0x295)+sects[scount].rva+0x299);
    cli_writeint32(&exe[pe+0x50], cli_readint32(&exe[pe+0x50])-sects[scount].vsz);

    structs = &exe[(0xffff&cli_readint32(&exe[pe+0x14]))+pe+0x18];
    for(i=0 ; i<scount ; i++) {
	  if (!CLI_ISCONTAINED(exe, exesz, structs, 0x28)) {
	    cli_dbgmsg("WWPack: structs pointer out of bounds\n");
	    return CL_EFORMAT;
	  }

      cli_writeint32(structs+8, sects[i].vsz);
      cli_writeint32(structs+12, sects[i].rva);
      cli_writeint32(structs+16, sects[i].vsz);
      cli_writeint32(structs+20, sects[i].rva);
      structs+=0x28;
    }
	if (!CLI_ISCONTAINED(exe, exesz, structs, 0x28)) {
	  cli_dbgmsg("WWPack: structs pointer out of bounds\n");
	  return CL_EFORMAT;
	}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -226,6 +226,12 @@
 	return CL_EFORMAT;
     exe[pe+6]=(uint8_t)scount;
     exe[pe+7]=(uint8_t)(scount>>8);
+    if (!CLI_ISCONTAINED(wwsect, sects[scount].rsz, wwsect+0x295, 4) ||
+        !CLI_ISCONTAINED(wwsect, sects[scount].rsz, wwsect+0x295+sects[scount].rva, 4) ||
+        !CLI_ISCONTAINED(wwsect, sects[scount].rsz, wwsect+0x295+sects[scount].rva+0x299, 4)) {
+        cli_dbgmsg("WWPack: unpack memory address out of bounds.\n");
+        return CL_EFORMAT;
+    }
     cli_writeint32(&exe[pe+0x28], cli_readint32(wwsect+0x295)+sects[scount].rva+0x299);
     cli_writeint32(&exe[pe+0x50], cli_readint32(&exe[pe+0x50])-sects[scount].vsz);
 
```
