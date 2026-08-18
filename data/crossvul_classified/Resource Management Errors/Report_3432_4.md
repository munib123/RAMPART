# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 3432_4
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3432_4`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 22-43 of the vulnerable file.

	MonoClassField *field;
	gpointer pa [2];
	MonoObject *delegate, *exc;

	field = mono_class_get_field_from_name (mono_defaults.appdomain_class, "ProcessExit");
	g_assert (field);

	delegate = *(MonoObject **)(((char *)domain->domain) + field->offset); 
	if (delegate == NULL)
		return;

	pa [0] = domain;
	pa [1] = NULL;
	mono_runtime_delegate_invoke (delegate, pa, &exc);
}

void
mono_runtime_shutdown (void)
{
	mono_domain_foreach (fire_process_exit_event, NULL);
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -39,5 +39,8 @@
 mono_runtime_shutdown (void)
 {
 	mono_domain_foreach (fire_process_exit_event, NULL);
+
+	/*From this point on, no more DM methods can be created. */
+	mono_reflection_shutdown ();
 }
 
```
