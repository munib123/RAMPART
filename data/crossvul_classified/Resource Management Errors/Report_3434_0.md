# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 3434_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3434_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 1019-1060 of the vulnerable file.

		
		internal->state &= ~ThreadState_Unstarted;

		THREAD_DEBUG (g_message ("%s: Started thread ID %"G_GSIZE_FORMAT" (handle %p)", __func__, tid, thread));

		LeaveCriticalSection (internal->synch_cs);
		return(thread);
	}
}

void ves_icall_System_Threading_InternalThread_Thread_free_internal (MonoInternalThread *this, HANDLE thread)
{
	MONO_ARCH_SAVE_REGS;

	THREAD_DEBUG (g_message ("%s: Closing thread %p, handle %p", __func__, this, thread));

	if (thread)
		CloseHandle (thread);

	if (this->synch_cs) {
		DeleteCriticalSection (this->synch_cs);
		g_free (this->synch_cs);
		this->synch_cs = NULL;
	}

	g_free (this->name);
}

static void mono_thread_start (MonoThread *thread)
{
	MonoInternalThread *internal = thread->internal_thread;

	THREAD_DEBUG (g_message ("%s: (%"G_GSIZE_FORMAT") Launching thread %p (%"G_GSIZE_FORMAT")", __func__, GetCurrentThreadId (), internal, (gsize)internal->tid));

	/* Only store the handle when the thread is about to be
	 * launched, to avoid the main thread deadlocking while trying
	 * to clean up a thread that will never be signalled.
	 */
	if (!handle_store (thread))
		return;

	ResumeThread (internal->handle);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1036,12 +1036,17 @@
 		CloseHandle (thread);
 
 	if (this->synch_cs) {
-		DeleteCriticalSection (this->synch_cs);
-		g_free (this->synch_cs);
+		CRITICAL_SECTION *synch_cs = this->synch_cs;
 		this->synch_cs = NULL;
-	}
-
-	g_free (this->name);
+		DeleteCriticalSection (synch_cs);
+		g_free (synch_cs);
+	}
+
+	if (this->name) {
+		void *name = this->name;
+		this->name = NULL;
+		g_free (name);
+	}
 }
 
 static void mono_thread_start (MonoThread *thread)
```
