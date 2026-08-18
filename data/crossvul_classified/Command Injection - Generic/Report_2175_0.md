# CrossVul Fix Pair: Improper Neutralization of Special Elements used in a Command ('Command Injection') in javascript
**Pair ID:** 2175_0
**Vulnerability Class:** Command Injection - Generic
**CWE:** CWE-77
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2175_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in a Command ('Command Injection') - Command injection vulnerabilities typically occur when: 1.

## Vulnerable Code
```javascript
Lines 76-110 of the vulnerable file.

	
	//TODO: check parameters type
	if(process.platform=="win32"){// call C++ binding
		if(!printer_helper.printDirect){
			error("Not supported, try to compile this package with MSC");
			return;
		}
		try{
			var res = printer_helper.printDirect(data, printer, docname, type, success, error);
			if(res===true){
				success();
			}else{
				error(Error("Something wrong"));
			}
		}catch (e){
			error(e);
		}
    }else if (!printer_helper.printDirect){// should be POSIX
        var temp_file_name = path.join(os.tmpDir(),"printing");
        fs.writeFileSync(temp_file_name, data);
        child_process.exec('lpr -P'+printer+' -oraw -r'+' '+temp_file_name, function(err, stdout, stderr){
            if (err !== null) {
                error('ERROR: ' + err);
                return;
            }
            if (stderr) {
                error('STD ERROR: ' + stderr);
                return;
            }
            success();
        });
    }else{
		error("Not supported");
	}
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -93,7 +93,7 @@
     }else if (!printer_helper.printDirect){// should be POSIX
         var temp_file_name = path.join(os.tmpDir(),"printing");
         fs.writeFileSync(temp_file_name, data);
-        child_process.exec('lpr -P'+printer+' -oraw -r'+' '+temp_file_name, function(err, stdout, stderr){
+        child_process.execFile('lpr', ['-P' + printer, '-oraw', '-r', temp_file_name], function(err, stdout, stderr){
             if (err !== null) {
                 error('ERROR: ' + err);
                 return;
```
