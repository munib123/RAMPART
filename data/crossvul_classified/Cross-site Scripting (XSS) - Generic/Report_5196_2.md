# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 5196_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5196_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 150-192 of the vulnerable file.

    }

    function deleteAllOccurrences() {
      vm.component.remove().then(function() {
        $rootScope.$emit('calendars:list');
        $mdDialog.hide();
      });
    }

    function toggleRawSource($event) {
      Calendar.$$resource.post(vm.component.pid + '/' + vm.component.id, "raw").then(function(data) {
        $mdDialog.hide();
        $mdDialog.show({
          parent: angular.element(document.body),
          targetEvent: $event,
          clickOutsideToClose: true,
          escapeToClose: true,
          template: [
            '<md-dialog flex="40" flex-sm="80" flex-xs="100" aria-label="' + l('View Raw Source') + '">',
            '  <md-dialog-content class="md-dialog-content">',
            '    <pre>',
            data,
            '    </pre>',
            '  </md-dialog-content>',
            '  <md-dialog-actions>',
            '    <md-button ng-click="close()">' + l('Close') + '</md-button>',
            '  </md-dialog-actions>',
            '</md-dialog>'
          ].join(''),
          controller: ComponentRawSourceDialogController
        });

        /**
         * @ngInject
         */
        ComponentRawSourceDialogController.$inject = ['scope', '$mdDialog'];
        function ComponentRawSourceDialogController(scope, $mdDialog) {
          scope.close = function() {
            $mdDialog.hide();
          };
        }
      });
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -167,23 +167,23 @@
           template: [
             '<md-dialog flex="40" flex-sm="80" flex-xs="100" aria-label="' + l('View Raw Source') + '">',
             '  <md-dialog-content class="md-dialog-content">',
-            '    <pre>',
-            data,
-            '    </pre>',
+            '    <pre ng-bind-html="data"></pre>',
             '  </md-dialog-content>',
             '  <md-dialog-actions>',
             '    <md-button ng-click="close()">' + l('Close') + '</md-button>',
             '  </md-dialog-actions>',
             '</md-dialog>'
           ].join(''),
-          controller: ComponentRawSourceDialogController
+          controller: ComponentRawSourceDialogController,
+          locals: { data: data }
         });
 
         /**
          * @ngInject
          */
-        ComponentRawSourceDialogController.$inject = ['scope', '$mdDialog'];
-        function ComponentRawSourceDialogController(scope, $mdDialog) {
+        ComponentRawSourceDialogController.$inject = ['scope', '$mdDialog', 'data'];
+        function ComponentRawSourceDialogController(scope, $mdDialog, data) {
+          scope.data = data;
           scope.close = function() {
             $mdDialog.hide();
           };
```
