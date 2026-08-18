# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 964_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `964_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 234-273 of the vulnerable file.

    grid.setColSorting('str,str');
    grid.setColumnMinWidth(100, 50);
    grid.setInitWidths("*");
    grid.setEditable(false);
    grid.init();
    win.progressOn();
    that.drive.core.request(
      that.drive.core.base.probedb()
    ).then((ret) => {
      if(ret['text'].indexOf("ERROR://") > -1){
        throw res["text"];
      }
      let _data = ret['text'].split('\n');
      let data_arr = [];
      for (let i = 0; i < _data.length; i ++) {
        let item = _data[i].split('\t');
        if(item.length<2){continue;}
        data_arr.push({
          id: i+1,
          data: [
            func_mapping.hasOwnProperty(item[0]) ? func_mapping[item[0]] : item[0],
            parseInt(item[1]) === 1 ? "√" : "×",
          ],
          style: parseInt(item[1]) === 1 ? "background-color:#ADF1B9": "",
        });
      }
      grid.parse({
        'rows': data_arr
      }, 'json');
      toastr.success(LANG['probedb']['success'], LANG_T['success']);
      win.progressOff();
    }).catch((err)=>{
      win.progressOff();
      toastr.error(JSON.stringify(err), LANG_T['error']);
    });
  }
}

// export default Database;
module.exports = Database;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -251,7 +251,7 @@
         data_arr.push({
           id: i+1,
           data: [
-            func_mapping.hasOwnProperty(item[0]) ? func_mapping[item[0]] : item[0],
+            func_mapping.hasOwnProperty(item[0]) ? func_mapping[item[0]] : antSword.noxss(item[0]),
             parseInt(item[1]) === 1 ? "√" : "×",
           ],
           style: parseInt(item[1]) === 1 ? "background-color:#ADF1B9": "",
```
