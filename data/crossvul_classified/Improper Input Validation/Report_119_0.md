# CrossVul Fix Pair: Improper Input Validation in cpp
**Pair ID:** 119_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `119_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```cpp
Lines 1147-1187 of the vulnerable file.

	 if(!file)
	 {
	    if(waiting_num>0)
	       break;
	    if(state==TARGET_REMOVE_OLD)
	       goto pre_TARGET_CHMOD;
	    goto pre_TARGET_MKDIR;
	 }
	 if(!FlagSet(DELETE))
	 {
	    if(FlagSet(REPORT_NOT_DELETED))
	    {
	       const char *target_name_rel=dir_file(target_relative_dir,file->name);
	       if(file->TypeIs(file->DIRECTORY))
		  Report(_("Old directory `%s' is not removed"),target_name_rel);
	       else
		  Report(_("Old file `%s' is not removed"),target_name_rel);
	    }
	    continue;
	 }
	 if(script)
	 {
	    ArgV args("rm");
	    if(file->TypeIs(file->DIRECTORY))
	    {
	       if(recursion_mode==RECURSION_NEVER)
		  args.setarg(0,"rmdir");
	       else
		  args.Append("-r");
	    }
	    args.Append(target_session->GetFileURL(file->name));
	    xstring_ca cmd(args.CombineQuoted());
	    fprintf(script,"%s\n",cmd.get());
	 }
	 if(!script_only)
	 {
	    ArgV *args=new ArgV("rm");
	    args->Append(file->name);
	    args->seek(1);
	    rmJob *j=new rmJob(target_session->Clone(),args);
	    args->CombineTo(j->cmdline);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1164,24 +1164,21 @@
 	    }
 	    continue;
 	 }
+	 bool use_rmdir = (file->TypeIs(file->DIRECTORY)
+			   && recursion_mode==RECURSION_NEVER);
 	 if(script)
 	 {
-	    ArgV args("rm");
-	    if(file->TypeIs(file->DIRECTORY))
-	    {
-	       if(recursion_mode==RECURSION_NEVER)
-		  args.setarg(0,"rmdir");
-	       else
-		  args.Append("-r");
-	    }
+	    ArgV args(use_rmdir?"rmdir":"rm");
+	    if(file->TypeIs(file->DIRECTORY) && !use_rmdir)
+	       args.Append("-r");
 	    args.Append(target_session->GetFileURL(file->name));
 	    xstring_ca cmd(args.CombineQuoted());
 	    fprintf(script,"%s\n",cmd.get());
 	 }
 	 if(!script_only)
 	 {
-	    ArgV *args=new ArgV("rm");
-	    args->Append(file->name);
+	    ArgV *args=new ArgV(use_rmdir?"rmdir":"rm");
+	    args->Append(dir_file(".",file->name));
 	    args->seek(1);
 	    rmJob *j=new rmJob(target_session->Clone(),args);
 	    args->CombineTo(j->cmdline);
@@ -1189,10 +1186,7 @@
 	    if(file->TypeIs(file->DIRECTORY))
 	    {
 	       if(recursion_mode==RECURSION_NEVER)
-	       {
-		  args->setarg(0,"rmdir");
 		  j->Rmdir();
-	       }
 	       else
 		  j->Recurse();
 	    }
@@ -1258,7 +1252,7 @@
 	 if(!script_only)
 	 {
 	    ArgV *a=new ArgV("chmod");
-	    a->Append(file->name);
+	    a->Append(dir_file(".",file->name));
 	    a->seek(1);
 	    ChmodJob *cj=new ChmodJob(target_session->Clone(),
 				 file->mode&~mode_mask,a);
@@ -1380,7 +1374,7 @@
 	 if(!script_only)
 	 {
 	    ArgV *args=new ArgV("rm");
-	    args->Append(file->name);
+	    args->Append(dir_file(".",file->name));
 	    args->seek(1);
 	    rmJob *j=new rmJob(source_session->Clone(),args);
 	    args->CombineTo(j->cmdline);
```
