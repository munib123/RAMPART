# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 5137_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5137_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 184-224 of the vulnerable file.

                $('#pma_console_options').find('input[name=current_query]').prop('checked', true);
                $('#pma_console_options').find('input[name=enter_executes]').prop('checked', false);
                $('#pma_console_options').find('input[name=dark_theme]').prop('checked', false);
                PMA_console.updateConfig();
            });

            $('#pma_console_options').find('input[name=enter_executes]').change(function() {
                PMA_consoleMessages.showInstructions(PMA_console.config.enterExecutes);
            });

            $(document).ajaxComplete(function (event, xhr, ajaxOptions) {
                if (ajaxOptions.dataType != 'json') {
                    return;
                }
                try {
                    var data = $.parseJSON(xhr.responseText);
                    PMA_console.ajaxCallback(data);
                } catch (e) {
                    console.log("Invalid JSON!" + e.message);
                    if (AJAX.xhr && AJAX.xhr.status === 0 && AJAX.xhr.statusText !== 'abort') {
                        PMA_ajaxShowMessage($('<div />',{'class':'error','html':PMA_messages.strRequestFailed+' ( '+AJAX.xhr.statusText+' )'}));
                        AJAX.active = false;
                        AJAX.xhr = null;
                    }
                }
            });

            PMA_console.isInitialized = true;
        }

        // Change console mode from cookie
        switch($.cookie('pma_console_mode')) {
            case 'collapse':
                PMA_console.collapse();
                break;
            /* jshint -W086 */// no break needed in default section
            default:
                $.cookie('pma_console_mode', 'info');
            case 'info':
            /* jshint +W086 */
                PMA_console.info();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -201,7 +201,7 @@
                 } catch (e) {
                     console.log("Invalid JSON!" + e.message);
                     if (AJAX.xhr && AJAX.xhr.status === 0 && AJAX.xhr.statusText !== 'abort') {
-                        PMA_ajaxShowMessage($('<div />',{'class':'error','html':PMA_messages.strRequestFailed+' ( '+AJAX.xhr.statusText+' )'}));
+                        PMA_ajaxShowMessage($('<div />',{'class':'error','html':PMA_messages.strRequestFailed+' ( '+escapeHtml(AJAX.xhr.statusText)+' )'}));
                         AJAX.active = false;
                         AJAX.xhr = null;
                     }
```
