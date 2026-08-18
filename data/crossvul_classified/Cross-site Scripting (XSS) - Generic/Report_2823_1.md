# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 2823_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2823_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 26-66 of the vulnerable file.

    switch(exception.code) {
        // overwrite default 503 handling and add a link to the wiki
        case 503:
            Ext.MessageBox.show({
                buttons: Ext.Msg.OK,
                icon: Ext.MessageBox.WARNING,
                title: i18n._('Service Unavailable'),
                msg: String.format(app.i18n._('The Filemanager is not configured correctly. Please refer to the {0}Tine 2.0 Admin FAQ{1} for configuration advice or contact your administrator.'),
                    '<a href="http://wiki.tine20.org/Admin_FAQ#The_message_.22filesdir_config_value_not_set.22_appears_in_the_logfile_and_I_can.27t_open_the_Filemanager" target="_blank">',
                    '</a>')
            });
            break;

        case 901:
            if (request) {
                Tine.log.debug('Tine.Filemanager.handleRequestException - request exception:');
                Tine.log.debug(exception);

                if (exception.existingnodesinfo) {
                    for (i = 0; i < exception.existingnodesinfo.length; i++) {
                        existingFilenames.push(exception.existingnodesinfo[i].name);
                    }
                }

                this.conflictConfirmWin = Tine.widgets.dialog.FileListDialog.openWindow({
                    modal: true,
                    allowCancel: false,
                    height: 180,
                    width: 300,
                    title: app.i18n._('Files already exists') + '. ' + app.i18n._('Do you want to replace the following file(s)?'),
                    text: existingFilenames.join('<br />'),
                    scope: this,
                    handler: function(button) {
                        var params = request.params,
                            uploadKey = exception.uploadKeyArray;
                        params.method = request.method;
                        params.forceOverwrite = true;

                        if (button == 'no') {
                            if (params.method == 'Filemanager.moveNodes') {
                                // reload grid
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -43,7 +43,7 @@
 
                 if (exception.existingnodesinfo) {
                     for (i = 0; i < exception.existingnodesinfo.length; i++) {
-                        existingFilenames.push(exception.existingnodesinfo[i].name);
+                        existingFilenames.push(Ext.util.Format.htmlEncode(exception.existingnodesinfo[i].name));
                     }
                 }
 
```
