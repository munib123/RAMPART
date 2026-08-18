# CrossVul Fix Pair: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') in c
**Pair ID:** 1167_0
**Vulnerability Class:** Classic Buffer Overflow
**CWE:** CWE-120
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1167_0`)

## Vulnerability Information & PoC

## Description
Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') - A buffer overflow condition exists when a product attempts to put more data in a buffer than it can hold, or when it attempts to put data in a memory area outside of the boundaries of a buffer.

## Vulnerable Code
```c
Lines 461-502 of the vulnerable file.

{
	if(!file) return 0;
	return openmpt_module_get_num_samples(file->mod);
}

LIBOPENMPT_MODPLUG_API unsigned int ModPlug_NumPatterns(ModPlugFile* file)
{
	if(!file) return 0;
	return openmpt_module_get_num_patterns(file->mod);
}

LIBOPENMPT_MODPLUG_API unsigned int ModPlug_NumChannels(ModPlugFile* file)
{
	if(!file) return 0;
	return openmpt_module_get_num_channels(file->mod);
}

LIBOPENMPT_MODPLUG_API unsigned int ModPlug_SampleName(ModPlugFile* file, unsigned int qual, char* buff)
{
	const char* str;
	unsigned int retval;
	size_t tmpretval;
	if(!file) return 0;
	str = openmpt_module_get_sample_name(file->mod,qual-1);
	if(!str){
		if(buff){
			*buff = '\0';
		}
		return 0;
	}
	tmpretval = strlen(str);
	if(tmpretval>=INT_MAX){
		tmpretval = INT_MAX-1;
	}
	retval = (int)tmpretval;
	if(buff){
		memcpy(buff,str,retval+1);
		buff[retval] = '\0';
	}
	openmpt_free_string(str);
	return retval;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -478,53 +478,35 @@
 LIBOPENMPT_MODPLUG_API unsigned int ModPlug_SampleName(ModPlugFile* file, unsigned int qual, char* buff)
 {
 	const char* str;
-	unsigned int retval;
-	size_t tmpretval;
+	char buf[32];
 	if(!file) return 0;
 	str = openmpt_module_get_sample_name(file->mod,qual-1);
-	if(!str){
-		if(buff){
-			*buff = '\0';
-		}
-		return 0;
-	}
-	tmpretval = strlen(str);
-	if(tmpretval>=INT_MAX){
-		tmpretval = INT_MAX-1;
-	}
-	retval = (int)tmpretval;
+	memset(buf,0,32);
+	if(str){
+		strncpy(buf,str,31);
+		openmpt_free_string(str);
+	}
 	if(buff){
-		memcpy(buff,str,retval+1);
-		buff[retval] = '\0';
-	}
-	openmpt_free_string(str);
-	return retval;
+		strncpy(buff,buf,32);
+	}
+	return (unsigned int)strlen(buf);
 }
 
 LIBOPENMPT_MODPLUG_API unsigned int ModPlug_InstrumentName(ModPlugFile* file, unsigned int qual, char* buff)
 {
 	const char* str;
-	unsigned int retval;
-	size_t tmpretval;
+	char buf[32];
 	if(!file) return 0;
 	str = openmpt_module_get_instrument_name(file->mod,qual-1);
-	if(!str){
-		if(buff){
-			*buff = '\0';
-		}
-		return 0;
-	}
-	tmpretval = strlen(str);
-	if(tmpretval>=INT_MAX){
-		tmpretval = INT_MAX-1;
-	}
-	retval = (int)tmpretval;
+	memset(buf,0,32);
+	if(str){
+		strncpy(buf,str,31);
+		openmpt_free_string(str);
+	}
 	if(buff){
-		memcpy(buff,str,retval+1);
-		buff[retval] = '\0';
-	}
-	openmpt_free_string(str);
-	return retval;
+		strncpy(buff,buf,32);
+	}
+	return (unsigned int)strlen(buf);
 }
 
 LIBOPENMPT_MODPLUG_API ModPlugNote* ModPlug_GetPattern(ModPlugFile* file, int pattern, unsigned int* numrows)
```
