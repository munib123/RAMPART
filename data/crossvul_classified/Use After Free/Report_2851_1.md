# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 2851_1
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2851_1`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 105-145 of the vulnerable file.

			snd_use_lock_use(&found->use_lock);
	}
	read_unlock(&client->ports_lock);
	return found;
}


/* initialize snd_seq_port_subs_info */
static void port_subs_info_init(struct snd_seq_port_subs_info *grp)
{
	INIT_LIST_HEAD(&grp->list_head);
	grp->count = 0;
	grp->exclusive = 0;
	rwlock_init(&grp->list_lock);
	init_rwsem(&grp->list_mutex);
	grp->open = NULL;
	grp->close = NULL;
}


/* create a port, port number is returned (-1 on failure) */
struct snd_seq_client_port *snd_seq_create_port(struct snd_seq_client *client,
						int port)
{
	unsigned long flags;
	struct snd_seq_client_port *new_port, *p;
	int num = -1;
	
	/* sanity check */
	if (snd_BUG_ON(!client))
		return NULL;

	if (client->num_ports >= SNDRV_SEQ_MAX_PORTS) {
		pr_warn("ALSA: seq: too many ports for client %d\n", client->number);
		return NULL;
	}

	/* create a new port */
	new_port = kzalloc(sizeof(*new_port), GFP_KERNEL);
	if (!new_port)
		return NULL;	/* failure, out of memory */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -122,7 +122,9 @@
 }
 
 
-/* create a port, port number is returned (-1 on failure) */
+/* create a port, port number is returned (-1 on failure);
+ * the caller needs to unref the port via snd_seq_port_unlock() appropriately
+ */
 struct snd_seq_client_port *snd_seq_create_port(struct snd_seq_client *client,
 						int port)
 {
@@ -151,6 +153,7 @@
 	snd_use_lock_init(&new_port->use_lock);
 	port_subs_info_init(&new_port->c_src);
 	port_subs_info_init(&new_port->c_dest);
+	snd_use_lock_use(&new_port->use_lock);
 
 	num = port >= 0 ? port : 0;
 	mutex_lock(&client->ports_mutex);
@@ -165,9 +168,9 @@
 	list_add_tail(&new_port->list, &p->list);
 	client->num_ports++;
 	new_port->addr.port = num;	/* store the port number in the port */
+	sprintf(new_port->name, "port-%d", num);
 	write_unlock_irqrestore(&client->ports_lock, flags);
 	mutex_unlock(&client->ports_mutex);
-	sprintf(new_port->name, "port-%d", num);
 
 	return new_port;
 }
```
