# CrossVul Fix Pair: Improper Certificate Validation in python
**Pair ID:** 4414_0
**Vulnerability Class:** Improper Certificate Validation
**CWE:** CWE-295
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4414_0`)

## Vulnerability Information & PoC

## Description
Improper Certificate Validation - When a certificate is invalid or malicious, it might allow an attacker to spoof a trusted entity by interfering in the communication path between the host and client.

## Vulnerable Code
```python
Lines 1290-1330 of the vulnerable file.

        entity['entityKey'] = {}
        entity['entityKey']['entityId'] = sub_data[7]
        entity['entityKey']['entityType'] = 'RL'
        payload.append(entity)
        logger.debug(json.dumps(payload))
        response = requests.delete(url, headers=headers, verify = not self.config['insecure'], json=payload)
        return response

    ###
    #
    # Code locations or Scans Stuff
    #
    ###
    
    def upload_scan(self, filename):
        url = self.get_apibase() + "/scan/data/?mode=replace"
        headers = self.get_headers()
        if filename.endswith('.json') or filename.endswith('.jsonld'):
            headers['Content-Type'] = 'application/ld+json'
            with open(filename,"r") as f:
                response = requests.post(url, headers=headers, data=f, verify=False)
        elif filename.endswith('.bdio'):
            headers['Content-Type'] = 'application/vnd.blackducksoftware.bdio+zip'
            with open(filename,"rb") as f:
                response = requests.post(url, headers=headers, data=f, verify=False)
        else:
            raise Exception("Unkown file type")
        return response
    
    def download_project_scans(self, project_name,version_name, output_folder=None):
        version = self.get_project_version_by_name(project_name,version_name)
        codelocations = self.get_version_codelocations(version)
        import os
        if output_folder:
            if not os.path.exists(output_folder):
                os.makedirs(output_folder, 0o755, True)
        
        result = []
        
        for item in codelocations['items']:
            links = item['_meta']['links']
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1307,11 +1307,11 @@
         if filename.endswith('.json') or filename.endswith('.jsonld'):
             headers['Content-Type'] = 'application/ld+json'
             with open(filename,"r") as f:
-                response = requests.post(url, headers=headers, data=f, verify=False)
+                response = requests.post(url, headers=headers, data=f, verify=not self.config['insecure'])
         elif filename.endswith('.bdio'):
             headers['Content-Type'] = 'application/vnd.blackducksoftware.bdio+zip'
             with open(filename,"rb") as f:
-                response = requests.post(url, headers=headers, data=f, verify=False)
+                response = requests.post(url, headers=headers, data=f, verify=not self.config['insecure'])
         else:
             raise Exception("Unkown file type")
         return response
@@ -1338,7 +1338,7 @@
                     if not os.path.exists(project_name):
                         os.mkdir(project_name)
                     pathname = os.path.join(project_name, filename)
-                responce = requests.get(url, headers=self.get_headers(), stream=True, verify=False)
+                responce = requests.get(url, headers=self.get_headers(), stream=True, verify=not self.config['insecure'])
                 with open(pathname, "wb") as f:
                     for data in responce.iter_content():
                         f.write(data)
```
