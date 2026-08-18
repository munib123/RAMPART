# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 1543_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1543_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 289-329 of the vulnerable file.


  for(;;){
    switch(checksoftirq2(force,cpu)){
    case -1:
      return -1;
    case 1:
      cpu++;
      break;
    case 0:
    default:
      return 0;
    }
  }
  return 0;
}
#endif



static char *get_pid_environ_val(pid_t pid,char *val){
  char temp[500];
  int i=0;
  int foundit=0;
  FILE *fp;

  sprintf(temp,"/proc/%d/environ",pid);

  fp=fopen(temp,"r");
  if(fp==NULL)
    return NULL;

  
  for(;;){
    temp[i]=fgetc(fp);    

    if(foundit==1 && (temp[i]==0 || temp[i]=='\0' || temp[i]==EOF)){
      char *ret;
      temp[i]=0;
      ret=malloc(strlen(temp)+10);
      sprintf(ret,"%s",temp);
      fclose(fp);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -306,7 +306,9 @@
 
 
 static char *get_pid_environ_val(pid_t pid,char *val){
-  char temp[500];
+  int temp_size = 500;
+  char *temp = malloc(temp_size);
+  
   int i=0;
   int foundit=0;
   FILE *fp;
@@ -319,6 +321,12 @@
 
   
   for(;;){
+    
+    if (i >= temp_size) {
+      temp_size *= 2;
+      temp = realloc(temp, temp_size);
+    }
+      
     temp[i]=fgetc(fp);    
 
     if(foundit==1 && (temp[i]==0 || temp[i]=='\0' || temp[i]==EOF)){
```
