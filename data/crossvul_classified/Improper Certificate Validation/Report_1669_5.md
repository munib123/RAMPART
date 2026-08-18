# CrossVul Fix Pair: Improper Certificate Validation in python
**Pair ID:** 1669_5
**Vulnerability Class:** Improper Certificate Validation
**CWE:** CWE-295
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1669_5`)

## Vulnerability Information & PoC

## Description
Improper Certificate Validation - When a certificate is invalid or malicious, it might allow an attacker to spoof a trusted entity by interfering in the communication path between the host and client.

## Vulnerable Code
```python
Lines 74-114 of the vulnerable file.

    update_command = UpdateCommand(context, 'update', _(d))
    update_command.add_option(name_option)
    update_command.add_option(description_option)
    update_command.add_option(update_note_option)
    update_command.add_option(OPTION_EXCHANGE_KEYS)
    context.cli.add_command(update_command)

    # Unregister Command
    d = 'unregisters this consumer from the Pulp server'
    unregister_command = UnregisterCommand(context, 'unregister', _(d))
    context.cli.add_command(unregister_command)

    # History Retrieval Command
    d = 'lists history of this consumer'
    context.cli.add_command(HistoryCommand(context, 'history', _(d)))

    d = 'displays the registration status of this consumer'
    context.cli.add_command(StatusCommand(context, 'status', _(d)))


def download(url, location):
    """
    Download files to the specified location.
    :param url: The file URL.
    :type url: str
    :param location: The absolute path to where the downloaded
        file is to be stored.
    :type location: str
    """
    request = urllib2.urlopen(url)
    try:
        content = request.read()
        fp = open(location, 'w+')
        try:
            fp.write(content)
        finally:
            fp.close()
    finally:
        request.close()


```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -91,43 +91,42 @@
     context.cli.add_command(StatusCommand(context, 'status', _(d)))
 
 
-def download(url, location):
+def write_to_location(location, content):
     """
-    Download files to the specified location.
-    :param url: The file URL.
-    :type url: str
-    :param location: The absolute path to where the downloaded
-        file is to be stored.
-    :type location: str
+    Write content to a path. Ensures that the entire path exists, creating directories if necessary.
+
+    :param location: path that should exist
+    :type  location: str
+    :param content: bits to be written to file
+    :type  content: str
     """
-    request = urllib2.urlopen(url)
-    try:
-        content = request.read()
-        fp = open(location, 'w+')
-        try:
-            fp.write(content)
-        finally:
-            fp.close()
-    finally:
-        request.close()
-
-
-def update_server_key(conf):
-    """
-    Download the server's RSA key and store in the location
-    specified in the configuration.
-    :param conf: The consumer configuration object.
-    :type conf: dict
-    """
-    host = conf['server']['host']
-    location = conf['server']['rsa_pub']
-    url = 'https://%s/pulp/static/rsa_pub.key' % host
     try:
         os.makedirs(os.path.dirname(location))
     except OSError, e:
         if e.errno != errno.EEXIST:
             raise
-    download(url, location)
+    try:
+        fp = open(location, 'w+')
+        fp.write(content)
+    finally:
+        fp.close()
+
+
+def update_server_key(command_inst):
+    """
+    Ensure that the server's public key stored on the consumer is up to date.
+
+    :param command_inst: instance of a CLI command
+    :type  command_inst: pulp.client.extensions.extensions.PulpCliCommand
+    """
+    try:
+        key_reply = command_inst.context.server.static.get_server_key()
+    except Exception, e:
+        msg = _('Download server RSA key failed [%(e)s]' % {'e': e})
+        command_inst.prompt.render_failure_message(msg)
+    else:
+        key_location = command_inst.context.config['server']['rsa_pub']
+        write_to_location(key_location, key_reply.response_body)
 
 
 # -- common exceptions --------------------------------------------------------
@@ -201,14 +200,7 @@
         finally:
             fp.close()
 
-        # download server public key
-
-        try:
-            update_server_key(self.context.config)
-        except Exception, e:
-            msg = _('Download server RSA key failed [%(e)s]' % {'e': e})
-            self.prompt.render_failure_message(msg)
-
+        update_server_key(self)
         self.prompt.render_success_message('Consumer [%s] successfully registered' % consumer_id)
 
 
@@ -250,11 +242,7 @@
             self.prompt.render_success_message('Consumer [%s] successfully updated' % consumer_id)
             if not kwargs.get(OPTION_EXCHANGE_KEYS.keyword):
                 return
-            try:
-                update_server_key(self.context.config)
-            except Exception, e:
-                msg = _('Download server RSA key failed [%(e)s]' % {'e': e})
-                self.prompt.render_failure_message(msg)
+            update_server_key(self)
         except NotFoundException:
             self.prompt.write('Consumer [%s] does not exist on the server' % consumer_id, tag='not-found')
 
```
