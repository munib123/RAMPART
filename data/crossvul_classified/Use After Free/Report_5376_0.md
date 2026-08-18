# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 5376_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5376_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 370-410 of the vulnerable file.

	idr_remove(&client->idr, handle->id);
	if (!RB_EMPTY_NODE(&handle->node))
		rb_erase(&handle->node, &client->handles);

	ion_buffer_remove_from_handle(buffer);
	ion_buffer_put(buffer);

	kfree(handle);
}

struct ion_buffer *ion_handle_buffer(struct ion_handle *handle)
{
	return handle->buffer;
}

static void ion_handle_get(struct ion_handle *handle)
{
	kref_get(&handle->ref);
}

static int ion_handle_put(struct ion_handle *handle)
{
	struct ion_client *client = handle->client;
	int ret;

	mutex_lock(&client->lock);
	ret = kref_put(&handle->ref, ion_handle_destroy);
	mutex_unlock(&client->lock);

	return ret;
}

static struct ion_handle *ion_handle_lookup(struct ion_client *client,
					    struct ion_buffer *buffer)
{
	struct rb_node *n = client->handles.rb_node;

	while (n) {
		struct ion_handle *entry = rb_entry(n, struct ion_handle, node);

		if (buffer < entry->buffer)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -387,13 +387,22 @@
 	kref_get(&handle->ref);
 }
 
-static int ion_handle_put(struct ion_handle *handle)
+static int ion_handle_put_nolock(struct ion_handle *handle)
+{
+	int ret;
+
+	ret = kref_put(&handle->ref, ion_handle_destroy);
+
+	return ret;
+}
+
+int ion_handle_put(struct ion_handle *handle)
 {
 	struct ion_client *client = handle->client;
 	int ret;
 
 	mutex_lock(&client->lock);
-	ret = kref_put(&handle->ref, ion_handle_destroy);
+	ret = ion_handle_put_nolock(handle);
 	mutex_unlock(&client->lock);
 
 	return ret;
@@ -417,18 +426,28 @@
 	return ERR_PTR(-EINVAL);
 }
 
-static struct ion_handle *ion_handle_get_by_id(struct ion_client *client,
+static struct ion_handle *ion_handle_get_by_id_nolock(struct ion_client *client,
 						int id)
 {
 	struct ion_handle *handle;
 
-	mutex_lock(&client->lock);
 	handle = idr_find(&client->idr, id);
 	if (handle)
 		ion_handle_get(handle);
+
+	return handle ? handle : ERR_PTR(-EINVAL);
+}
+
+struct ion_handle *ion_handle_get_by_id(struct ion_client *client,
+						int id)
+{
+	struct ion_handle *handle;
+
+	mutex_lock(&client->lock);
+	handle = ion_handle_get_by_id_nolock(client, id);
 	mutex_unlock(&client->lock);
 
-	return handle ? handle : ERR_PTR(-EINVAL);
+	return handle;
 }
 
 static bool ion_handle_validate(struct ion_client *client,
@@ -532,22 +551,28 @@
 }
 EXPORT_SYMBOL(ion_alloc);
 
-void ion_free(struct ion_client *client, struct ion_handle *handle)
+static void ion_free_nolock(struct ion_client *client, struct ion_handle *handle)
 {
 	bool valid_handle;
 
 	BUG_ON(client != handle->client);
 
-	mutex_lock(&client->lock);
 	valid_handle = ion_handle_validate(client, handle);
 
 	if (!valid_handle) {
 		WARN(1, "%s: invalid handle passed to free.\n", __func__);
-		mutex_unlock(&client->lock);
 		return;
 	}
+	ion_handle_put_nolock(handle);
+}
+
+void ion_free(struct ion_client *client, struct ion_handle *handle)
+{
+	BUG_ON(client != handle->client);
+
+	mutex_lock(&client->lock);
+	ion_free_nolock(client, handle);
 	mutex_unlock(&client->lock);
-	ion_handle_put(handle);
 }
 EXPORT_SYMBOL(ion_free);
 
@@ -1332,11 +1357,15 @@
 	{
 		struct ion_handle *handle;
 
-		handle = ion_handle_get_by_id(client, data.handle.handle);
-		if (IS_ERR(handle))
+		mutex_lock(&client->lock);
+		handle = ion_handle_get_by_id_nolock(client, data.handle.handle);
+		if (IS_ERR(handle)) {
+			mutex_unlock(&client->lock);
 			return PTR_ERR(handle);
-		ion_free(client, handle);
-		ion_handle_put(handle);
+		}
+		ion_free_nolock(client, handle);
+		ion_handle_put_nolock(handle);
+		mutex_unlock(&client->lock);
 		break;
 	}
 	case ION_IOC_SHARE:
```
