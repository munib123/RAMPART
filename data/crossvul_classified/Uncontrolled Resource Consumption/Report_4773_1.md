# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 4773_1
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4773_1`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 540-580 of the vulnerable file.

%
%    o module_type: the module type: MagickImageCoderModule or
%      MagickImageFilterModule.
%
%    o path: the path associated with the filename.
%
%    o exception: return any errors or warnings in this structure.
%
*/
static MagickBooleanType GetMagickModulePath(const char *filename,
  MagickModuleType module_type,char *path,ExceptionInfo *exception)
{
  char
    *module_path;

  assert(filename != (const char *) NULL);
  (void) LogMagickEvent(TraceEvent,GetMagickModule(),"%s",filename);
  assert(path != (char *) NULL);
  assert(exception != (ExceptionInfo *) NULL);
  (void) CopyMagickString(path,filename,MaxTextExtent);
  module_path=(char *) NULL;
  switch (module_type)
  {
    case MagickImageCoderModule:
    default:
    {
      (void) LogMagickEvent(ModuleEvent,GetMagickModule(),
        "Searching for coder module file \"%s\" ...",filename);
      module_path=GetEnvironmentValue("MAGICK_CODER_MODULE_PATH");
#if defined(MAGICKCORE_CODER_PATH)
      if (module_path == (char *) NULL)
        module_path=AcquireString(MAGICKCORE_CODER_PATH);
#endif
      break;
    }
    case MagickImageFilterModule:
    {
      (void) LogMagickEvent(ModuleEvent,GetMagickModule(),
        "Searching for filter module file \"%s\" ...",filename);
      module_path=GetEnvironmentValue("MAGICK_CODER_FILTER_PATH");
#if defined(MAGICKCORE_FILTER_PATH)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -557,6 +557,15 @@
   assert(path != (char *) NULL);
   assert(exception != (ExceptionInfo *) NULL);
   (void) CopyMagickString(path,filename,MaxTextExtent);
+#if defined(MAGICKCORE_INSTALLED_SUPPORT)
+  if (strstr(path,"../") != (char *) NULL)
+    {
+      errno=EPERM;
+      (void) ThrowMagickException(exception,GetMagickModule(),PolicyError,
+        "NotAuthorized","`%s'",path);
+      return(MagickFalse);
+    }
+#endif
   module_path=(char *) NULL;
   switch (module_type)
   {
```
