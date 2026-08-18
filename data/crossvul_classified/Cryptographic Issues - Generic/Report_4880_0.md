# CrossVul Fix Pair: Cryptographic Issues in javascript
**Pair ID:** 4880_0
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4880_0`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```javascript
Lines 1-27 of the vulnerable file.

/**
 * New node file
 */

var fs = require('fs');
var url = require('url');
var http = require('http');
var os = require('os');
var path = require('path');
var exec = require('child_process').exec;

var installerURL = 'http://public.dhe.ibm.com/ibmdl/export/pub/software/data/db2/drivers/odbc_cli/';
var CURRENT_DIR = process.cwd();
var DOWNLOAD_DIR = path.resolve(CURRENT_DIR, 'installer');
var INSTALLER_FILE; 
installerURL = process.env.IBM_DB_INSTALLER_URL || installerURL;
installerURL = installerURL + "/";

//Function to download file using HTTP.get
var download_file_httpget = function(file_url) {
    var readStream;
    var writeStream;
    var platform = os.platform();
    var arch = os.arch();
    var endian = os.endianness();
    var installerfileURL;
    
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,12 +4,12 @@
 
 var fs = require('fs');
 var url = require('url');
-var http = require('http');
+var http = require('https');
 var os = require('os');
 var path = require('path');
 var exec = require('child_process').exec;
 
-var installerURL = 'http://public.dhe.ibm.com/ibmdl/export/pub/software/data/db2/drivers/odbc_cli/';
+var installerURL = 'https://public.dhe.ibm.com/ibmdl/export/pub/software/data/db2/drivers/odbc_cli';
 var CURRENT_DIR = process.cwd();
 var DOWNLOAD_DIR = path.resolve(CURRENT_DIR, 'installer');
 var INSTALLER_FILE; 
@@ -31,7 +31,6 @@
     var IBM_DB_HOME, IBM_DB_INCLUDE, IBM_DB_LIB, IBM_DB_DIR;
     
     if(platform == 'win32') {
-        
         if(arch == 'x64') {
             var BUILD_FILE = path.resolve(CURRENT_DIR, 'build.zip');
             readStream = fs.createReadStream(BUILD_FILE);
@@ -220,7 +219,11 @@
             }
             data.copy( buf, byteIndex );
             byteIndex += data.length;
+            process.stdout.write((platform == 'win32') ? "\033[0G": "\r");
+            process.stdout.write("Downloaded " + (100.0 * byteIndex / fileLength).toFixed(2) + 
+                                 "% (" + byteIndex + " bytes)");
          }).on('end', function() {
+             console.log("\n");
              if( byteIndex != buf.length ) 
              {
                 console.log( "Error downloading IBM ODBC and CLI Driver from " +
@@ -254,7 +257,7 @@
         else 
         {
             var targz = require('targz');
-            var compress = targz.decompress({src: INSTALLER_FILE, dest: "DOWNLOAD_DIR"}, function(err){
+            var compress = targz.decompress({src: INSTALLER_FILE, dest: DOWNLOAD_DIR}, function(err){
               if(err) {
                 console.log(err);
                 process.exit(1);
@@ -294,7 +297,7 @@
             if(platform == 'darwin' && arch == 'x64') 
             {
                 // Run the install_name_tool
-                var nameToolCommand = "install_name_tool -change libdb2.dylib $IBM_DB_HOME/lib/libdb2.dylib ./build/Release/odbc_bindings.node"
+                var nameToolCommand = "install_name_tool -change libdb2.dylib $IBM_DB_HOME/lib/libdb2.dylib ./build/Release/odbc_bindings.node" ;
                 var nameToolCmdProcess = exec(nameToolCommand , 
                   function (error1, stdout1, stderr1) {
                     if (error1 !== null) {
@@ -341,7 +344,7 @@
     {
         var options = {
              host: url.parse(installerfileURL).host,
-             port: 80,
+             port: 443,
              path: url.parse(installerfileURL).pathname
             };
         var proxyStr;
```
