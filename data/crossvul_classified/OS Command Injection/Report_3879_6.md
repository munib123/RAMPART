# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in javascript
**Pair ID:** 3879_6
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3879_6`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```javascript
Lines 9-49 of the vulnerable file.

//
//	This program is distributed in the hope that it will be useful,
//	but WITHOUT ANY WARRANTY; without even the implied warranty of
//	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//	GNU General Public License for more details.
//
//	You should have received a copy of the GNU General Public License
//	along with this program.  If not, see <http://www.gnu.org/licenses/>.
//

// 2.
//	If you purchased an openITCOCKPIT Enterprise Edition you can use this file
//	under the terms of the openITCOCKPIT Enterprise Edition license agreement.
//	License agreement and license key will be shipped with the order
//	confirmation.

App.Controllers.CommandsAddController = Frontend.AppController.extend({

    argumentNames: null,

    components: ['WebsocketSudo', 'Ajaxloader'],

    _initialize: function(){
        this.Ajaxloader.setup();

        /*
         * Bind the click event for the Add button of the human command args
         */
        $('#add_new_arg').click(function(){
            this.addArgument();
        }.bind(this));

        /*
         * Bind click event to load user defined macros
         */
        $('#loadMacrosOberview').click(function(){
            $('#macros_loader').show();
            $.ajax({
                url: "/Commands/loadMacros/",
                type: "POST",
                cache: false,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -26,7 +26,7 @@
 
     argumentNames: null,
 
-    components: ['WebsocketSudo', 'Ajaxloader'],
+    components: ['Ajaxloader'],
 
     _initialize: function(){
         this.Ajaxloader.setup();
@@ -66,44 +66,6 @@
             $this = $(this);
             $this.parent().parent().remove();
         });
-
-        this.$jqconsole = null;
-        this.WebsocketSudo.setup(this.getVar('websocket_url'), this.getVar('akey'));
-        this.WebsocketSudo._errorCallback = function(){
-            $('#error_msg').html('<div class="alert alert-danger alert-block"><a href="#" data-dismiss="alert" class="close">×</a><h5 class="alert-heading"><i class="fa fa-warning"></i> Error</h5>Could not connect to SudoWebsocket Server</div>');
-            $('#console').block({
-                fadeIn: 1000,
-                message: '<i class="fa fa-minus-circle fa-5x"></i>',
-                theme: false
-            });
-            $('.blockElement').css({
-                'background-color': '',
-                'border': 'none',
-                'color': '#FFFFFF'
-            });
-        }
-        this.WebsocketSudo.connect();
-        this.loadConsole();
-        this.WebsocketSudo._callback = function(transmitted){
-            this.$jqconsole.Write(transmitted.payload, 'jqconsole-output');
-        }.bind(this);
-    },
-
-    loadConsole: function(){
-        this.$jqconsole = $('#console').jqconsole('', 'nagios$ ');
-        this.$jqconsole.Write(this.getVar('console_welcome'));
-        var startPrompt = function(){
-            // Start the prompt with history enabled.
-            var self = this;
-            self.$jqconsole.Prompt(true, function(input){
-                // Output input with the class jqconsole-output.
-                //jqconsole.Write(input + '\n', 'jqconsole-output');
-                self.WebsocketSudo.send(self.WebsocketSudo.toJson('execute_nagios_command', input));
-                // Restart the prompt.
-                startPrompt();
-            });
-        }.bind(this);
-        startPrompt();
     },
 
     addArgument: function(){
```
