# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 3433_1
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3433_1`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 37-77 of the vulnerable file.


typedef struct DomainFinalizationReq {
	MonoDomain *domain;
	HANDLE done_event;
} DomainFinalizationReq;

#ifdef PLATFORM_WINCE /* FIXME: add accessors to gc.dll API */
extern void (*__imp_GC_finalizer_notifier)(void);
#define GC_finalizer_notifier __imp_GC_finalizer_notifier
extern int __imp_GC_finalize_on_demand;
#define GC_finalize_on_demand __imp_GC_finalize_on_demand
#endif

static gboolean gc_disabled = FALSE;

static gboolean finalizing_root_domain = FALSE;

#define mono_finalizer_lock() EnterCriticalSection (&finalizer_mutex)
#define mono_finalizer_unlock() LeaveCriticalSection (&finalizer_mutex)
static CRITICAL_SECTION finalizer_mutex;

static GSList *domains_to_finalize= NULL;
static MonoMList *threads_to_finalize = NULL;

static MonoInternalThread *gc_thread;

static void object_register_finalizer (MonoObject *obj, void (*callback)(void *, void*));

static void mono_gchandle_set_target (guint32 gchandle, MonoObject *obj);

#ifndef HAVE_NULL_GC
static HANDLE pending_done_event;
static HANDLE shutdown_event;
#endif

static void
add_thread_to_finalize (MonoInternalThread *thread)
{
	mono_finalizer_lock ();
	if (!threads_to_finalize)
		MONO_GC_REGISTER_ROOT_SINGLE (threads_to_finalize);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -54,6 +54,7 @@
 #define mono_finalizer_lock() EnterCriticalSection (&finalizer_mutex)
 #define mono_finalizer_unlock() LeaveCriticalSection (&finalizer_mutex)
 static CRITICAL_SECTION finalizer_mutex;
+static CRITICAL_SECTION reference_queue_mutex;
 
 static GSList *domains_to_finalize= NULL;
 static MonoMList *threads_to_finalize = NULL;
@@ -64,6 +65,7 @@
 
 static void mono_gchandle_set_target (guint32 gchandle, MonoObject *obj);
 
+static void reference_queue_proccess_all (void);
 #ifndef HAVE_NULL_GC
 static HANDLE pending_done_event;
 static HANDLE shutdown_event;
@@ -1065,6 +1067,8 @@
 		mono_attach_maybe_start ();
 #endif
 
+		reference_queue_proccess_all ();
+
 		if (domains_to_finalize) {
 			mono_finalizer_lock ();
 			if (domains_to_finalize) {
@@ -1083,6 +1087,7 @@
 		 */
 		mono_gc_invoke_finalizers ();
 
+
 		SetEvent (pending_done_event);
 	}
 
@@ -1097,6 +1102,7 @@
 	InitializeCriticalSection (&allocator_section);
 
 	InitializeCriticalSection (&finalizer_mutex);
+	InitializeCriticalSection (&reference_queue_mutex);
 
 	MONO_GC_REGISTER_ROOT_FIXED (gc_handles [HANDLE_NORMAL].entries);
 	MONO_GC_REGISTER_ROOT_FIXED (gc_handles [HANDLE_PINNED].entries);
@@ -1174,6 +1180,7 @@
 	DeleteCriticalSection (&handle_section);
 	DeleteCriticalSection (&allocator_section);
 	DeleteCriticalSection (&finalizer_mutex);
+	DeleteCriticalSection (&reference_queue_mutex);
 }
 
 #else
@@ -1292,3 +1299,137 @@
 	return mono_object_new_specific (vtable);
 }
 #endif
+
+
+static MonoReferenceQueue *ref_queues;
+
+static void
+ref_list_remove_element (RefQueueEntry **prev, RefQueueEntry *element)
+{
+	do {
+		/* Guard if head is changed concurrently. */
+		while (*prev != element)
+			prev = &(*prev)->next;
+	} while (prev && InterlockedCompareExchangePointer ((void*)prev, element->next, element) != element);
+}
+
+static void
+ref_list_push (RefQueueEntry **head, RefQueueEntry *value)
+{
+	RefQueueEntry *current;
+	do {
+		current = *head;
+		value->next = current;
+	} while (InterlockedCompareExchangePointer ((void*)head, value, current) != current);
+}
+
+static void
+reference_queue_proccess (MonoReferenceQueue *queue)
+{
+	RefQueueEntry **iter = &queue->queue;
+	RefQueueEntry *entry;
+	while ((entry = *iter)) {
+		if (queue->should_be_deleted || !mono_gc_weak_link_get (&entry->dis_link)) {
+			ref_list_remove_element (iter, entry);
+			mono_gc_weak_link_remove (&entry->dis_link);
+			queue->callback (entry->user_data);
+			g_free (entry);
+		} else {
+			iter = &entry->next;
+		}
+	}
+}
+
+static void
+reference_queue_proccess_all (void)
+{
+	MonoReferenceQueue **iter;
+	MonoReferenceQueue *queue = ref_queues;
+	for (; queue; queue = queue->next)
+		reference_queue_proccess (queue);
+
+restart:
+	EnterCriticalSection (&reference_queue_mutex);
+	for (iter = &ref_queues; *iter;) {
+		queue = *iter;
+		if (!queue->should_be_deleted) {
+			iter = &queue->next;
+			continue;
+		}
+		if (queue->queue) {
+			LeaveCriticalSection (&reference_queue_mutex);
+			reference_queue_proccess (queue);
+			goto restart;
+		}
+		*iter = queue->next;
+		g_free (queue);
+	}
+	LeaveCriticalSection (&reference_queue_mutex);
+}
+
+/**
+ * mono_gc_reference_queue_new:
+ * @callback callback used when processing dead entries.
+ *
+ * Create a new reference queue used to process collected objects.
+ * A reference queue let you queue the pair (managed object, user data).
+ * Once the managed object is collected @callback will be called
+ * in the finalizer thread with 'user data' as argument.
+ *
+ * The callback is called without any locks held.
+ */
+MonoReferenceQueue*
+mono_gc_reference_queue_new (mono_reference_queue_callback callback)
+{
+	MonoReferenceQueue *res = g_new0 (MonoReferenceQueue, 1);
+	res->callback = callback;
+
+	EnterCriticalSection (&reference_queue_mutex);
+	res->next = ref_queues;
+	ref_queues = res;
+	LeaveCriticalSection (&reference_queue_mutex);
+
+	return res;
+}
+
+/**
+ * mono_gc_reference_queue_add:
+ * @queue the queue to add the reference to.
+ * @obj the object to be watched for collection
+ * @user_data parameter to be passed to the queue callback
+ *
+ * Queue an object to be watched for collection.
+ *
+ * @returns false if the queue is scheduled to be freed.
+ */
+gboolean
+mono_gc_reference_queue_add (MonoReferenceQueue *queue, MonoObject *obj, void *user_data)
+{
+	RefQueueEntry *head;
+	RefQueueEntry *entry;
+	if (queue->should_be_deleted)
+		return FALSE;
+
+	entry = g_new0 (RefQueueEntry, 1);
+	entry->user_data = user_data;
+	mono_gc_weak_link_add (&entry->dis_link, obj, TRUE);
+	ref_list_push (&queue->queue, entry);
+	return TRUE;
+}
+
+/**
+ * mono_gc_reference_queue_free:
+ * @queue the queue that should be deleted.
+ *
+ * This operation signals that @queue should be deleted. This operation is deferred
+ * as it happens on the finalizer thread.
+ *
+ * After this call, no further objects can be queued. It's the responsibility of the
+ * caller to make sure that no further attempt to access queue will be made.
+ */
+void
+mono_gc_reference_queue_free (MonoReferenceQueue *queue)
+{
+	queue->should_be_deleted = TRUE;
+}
+
```
