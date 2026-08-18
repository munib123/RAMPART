# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in python
**Pair ID:** 4657_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4657_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```python
Lines 28-68 of the vulnerable file.


from Helper import Process

import magic

def rreplace(s, old, new, occurrence):
    li = s.rsplit(old, occurrence)
    return new.join(li)


if __name__ == '__main__':
    publisher.port = 6380
    publisher.channel = 'Script'
    processed_paste = 0
    time_1 = time.time()

    config_section = 'Global'

    p = Process(config_section)

    PASTES_FOLDER = os.path.join(os.environ['AIL_HOME'], p.config.get("Directories", "pastes"))
    PASTES_FOLDERS = PASTES_FOLDER + '/'

    # LOGGING #
    publisher.info("Feed Script started to receive & publish.")

    while True:

        message = p.get_from_set()
        # Recovering the streamed message informations.
        if message is not None:
            splitted = message.split()
            if len(splitted) == 2:
                paste, gzip64encoded = splitted
            else:
                # TODO Store the name of the empty paste inside a Redis-list.
                print("Empty Paste: not processed")
                publisher.debug("Empty Paste: {0} not processed".format(message))
                continue
        else:
            print("Empty Queues: Waiting...")
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -45,8 +45,10 @@
 
     p = Process(config_section)
 
+    # get and sanityze PASTE DIRECTORY
     PASTES_FOLDER = os.path.join(os.environ['AIL_HOME'], p.config.get("Directories", "pastes"))
     PASTES_FOLDERS = PASTES_FOLDER + '/'
+    PASTES_FOLDERS = os.path.join(os.path.realpath(PASTES_FOLDERS), '')
 
     # LOGGING #
     publisher.info("Feed Script started to receive & publish.")
@@ -75,6 +77,10 @@
             time.sleep(1)
             continue
 
+        # remove PASTES_FOLDER from item path (crawled item + submited)
+        if PASTES_FOLDERS in paste:
+            paste = paste.replace(PASTES_FOLDERS, '', 1)
+
         file_name_paste = paste.split('/')[-1]
         if len(file_name_paste)>255:
             new_file_name_paste = '{}{}.gz'.format(file_name_paste[:215], str(uuid.uuid4()))
@@ -82,33 +88,35 @@
 
         # Creating the full filepath
         filename = os.path.join(PASTES_FOLDER, paste)
+        filename = os.path.realpath(filename)
 
-        dirname = os.path.dirname(filename)
-        if not os.path.exists(dirname):
-            os.makedirs(dirname)
+        # incorrect filename
+        if not os.path.commonprefix([filename, PASTES_FOLDER]) == PASTES_FOLDER:
+            print('Path traversal detected {}'.format(filename))
+            publisher.warning('Global; Path traversal detected')
+        else:
+            dirname = os.path.dirname(filename)
+            if not os.path.exists(dirname):
+                os.makedirs(dirname)
 
-        decoded = base64.standard_b64decode(gzip64encoded)
+            decoded = base64.standard_b64decode(gzip64encoded)
 
-        with open(filename, 'wb') as f:
-            f.write(decoded)
-        '''try:
-            decoded2 = gunzip_bytes_obj(decoded)
-        except:
-            decoded2 =''
+            with open(filename, 'wb') as f:
+                f.write(decoded)
+            '''try:
+                decoded2 = gunzip_bytes_obj(decoded)
+            except:
+                decoded2 =''
 
-        type = magic.from_buffer(decoded2, mime=True)
+            type = magic.from_buffer(decoded2, mime=True)
 
-        if type!= 'text/x-c++' and type!= 'text/html' and type!= 'text/x-c' and type!= 'text/x-python' and type!= 'text/x-php' and type!= 'application/xml' and type!= 'text/x-shellscript' and type!= 'text/plain' and type!= 'text/x-diff' and type!= 'text/x-ruby':
+            if type!= 'text/x-c++' and type!= 'text/html' and type!= 'text/x-c' and type!= 'text/x-python' and type!= 'text/x-php' and type!= 'application/xml' and type!= 'text/x-shellscript' and type!= 'text/plain' and type!= 'text/x-diff' and type!= 'text/x-ruby':
 
-            print('-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------')
-            print(filename)
-            print(type)
-            print('-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------')
-        '''
+                print('-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------')
+                print(filename)
+                print(type)
+                print('-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------')
+            '''
 
-        # remove PASTES_FOLDER from item path (crawled item + submited)
-        if PASTES_FOLDERS in paste:
-            paste = paste.replace(PASTES_FOLDERS, '', 1)
-
-        p.populate_set_out(paste)
-        processed_paste+=1
+            p.populate_set_out(paste)
+            processed_paste+=1
```
