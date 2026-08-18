# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 2851_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2851_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 1242-1282 of the vulnerable file.

	/* fill the info fields */
	if (client_info->name[0])
		strlcpy(client->name, client_info->name, sizeof(client->name));

	client->filter = client_info->filter;
	client->event_lost = client_info->event_lost;
	memcpy(client->event_filter, client_info->event_filter, 32);

	return 0;
}


/* 
 * CREATE PORT ioctl() 
 */
static int snd_seq_ioctl_create_port(struct snd_seq_client *client, void *arg)
{
	struct snd_seq_port_info *info = arg;
	struct snd_seq_client_port *port;
	struct snd_seq_port_callback *callback;

	/* it is not allowed to create the port for an another client */
	if (info->addr.client != client->number)
		return -EPERM;

	port = snd_seq_create_port(client, (info->flags & SNDRV_SEQ_PORT_FLG_GIVEN_PORT) ? info->addr.port : -1);
	if (port == NULL)
		return -ENOMEM;

	if (client->type == USER_CLIENT && info->kernel) {
		snd_seq_delete_port(client, port->addr.port);
		return -EINVAL;
	}
	if (client->type == KERNEL_CLIENT) {
		if ((callback = info->kernel) != NULL) {
			if (callback->owner)
				port->owner = callback->owner;
			port->private_data = callback->private_data;
			port->private_free = callback->private_free;
			port->event_input = callback->event_input;
			port->c_src.open = callback->subscribe;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1259,6 +1259,7 @@
 	struct snd_seq_port_info *info = arg;
 	struct snd_seq_client_port *port;
 	struct snd_seq_port_callback *callback;
+	int port_idx;
 
 	/* it is not allowed to create the port for an another client */
 	if (info->addr.client != client->number)
@@ -1269,7 +1270,9 @@
 		return -ENOMEM;
 
 	if (client->type == USER_CLIENT && info->kernel) {
-		snd_seq_delete_port(client, port->addr.port);
+		port_idx = port->addr.port;
+		snd_seq_port_unlock(port);
+		snd_seq_delete_port(client, port_idx);
 		return -EINVAL;
 	}
 	if (client->type == KERNEL_CLIENT) {
@@ -1290,6 +1293,7 @@
 
 	snd_seq_set_port_info(port, info);
 	snd_seq_system_client_ev_port_start(port->addr.client, port->addr.port);
+	snd_seq_port_unlock(port);
 
 	return 0;
 }
```
