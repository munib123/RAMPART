# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 2823_4
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2823_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 46-86 of the vulnerable file.

        Ext.each(this.items, function(item) {
            item.template = buttonTpl;
        }, this);
        
        this.supr().initComponent.call(this);
    },
    
    getItems: function() {
        return [{
            text: Tine.title,
            hidden: !this.showMainMenu,
            menu: {
                id: 'Tinebase_System_Menu', 
                items: this.getMainActions()
        }},
        '->',
        this.actionLearnMore,
        // TODO add a bigger spacer here?
        { xtype: 'spacer' },
        {
            text: String.format(i18n._('User: {0}'), Tine.Tinebase.registry.get('currentAccount').accountDisplayName),
            menu: this.getUserActions(),
            menuAlign: 'tr-br',
            iconCls: Tine.Tinebase.registry.get('userAccountChanged') ? 'renderer_accountUserChangedIcon' : 'renderer_accountUserIcon'
        },
        this.onlineStatus, 
        this.action_logout];
    },
    
    /**
     * returns all main actions
     * 
     * @return {Array}
     */
    getMainActions: function() {
        if (! this.mainActions) {
            this.mainActions = [
                this.action_aboutTine,
                this.action_loadTutorial,
                '-',
                this.getUserActions(),
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -63,7 +63,7 @@
         // TODO add a bigger spacer here?
         { xtype: 'spacer' },
         {
-            text: String.format(i18n._('User: {0}'), Tine.Tinebase.registry.get('currentAccount').accountDisplayName),
+            text: Ext.util.Format.htmlEncode(String.format(i18n._('User: {0}'), Tine.Tinebase.registry.get('currentAccount').accountDisplayName)),
             menu: this.getUserActions(),
             menuAlign: 'tr-br',
             iconCls: Tine.Tinebase.registry.get('userAccountChanged') ? 'renderer_accountUserChangedIcon' : 'renderer_accountUserIcon'
```
