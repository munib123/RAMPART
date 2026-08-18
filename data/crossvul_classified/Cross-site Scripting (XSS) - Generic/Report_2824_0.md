# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 2824_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2824_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 242-282 of the vulnerable file.


// Static Methods

/**
 * tid renderer
 * 
 * @private
 * @return {String} HTML
 */
Tine.Addressbook.ContactGridPanel.contactTypeRenderer = function(data, cell, record) {
    var i18n = Tine.Tinebase.appMgr.get('Addressbook').i18n,
        hasAccount = ((record.get && record.get('account_id')) || record.account_id),
        cssClass = hasAccount ? 'renderer_typeAccountIcon' : 'renderer_typeContactIcon',
        qtipText = Tine.Tinebase.common.doubleEncode(hasAccount ? i18n._('Contact of a user account') : i18n._('Contact'));
    
    return '<div ext:qtip="' + qtipText + '" style="background-position:0px;" class="' + cssClass + '">&#160</div>';
};

Tine.Addressbook.ContactGridPanel.displayNameRenderer = function(data) {
    var i18n = Tine.Tinebase.appMgr.get('Addressbook').i18n;
    return data ? data : ('<div class="renderer_displayNameRenderer_noName">' + i18n._('No name') + '</div>');
};

Tine.Addressbook.ContactGridPanel.countryRenderer = function(data) {
    data = Locale.getTranslationData('CountryList', data);
    return data;
};

/**
 * Statically constructs the columns used to represent a contact. Reused by ListMemberGridPanel
 *
 */
Tine.Addressbook.ContactGridPanel.getBaseColumns = function(i18n) {
    return [
        { id: 'type', header: i18n._('Type'), dataIndex: 'type', width: 30, renderer: Tine.Addressbook.ContactGridPanel.contactTypeRenderer.createDelegate(this), hidden: false },
        { id: 'tags', header: i18n._('Tags'), dataIndex: 'tags', width: 50, renderer: Tine.Tinebase.common.tagsRenderer, sortable: false, hidden: false  },
        { id: 'salutation', header: i18n._('Salutation'), dataIndex: 'salutation', renderer: Tine.Tinebase.widgets.keyfield.Renderer.get('Addressbook', 'contactSalutation') },
        {
            id: 'container_id',
            dataIndex: 'container_id',
            header: Tine.Addressbook.Model.Contact.getContainerName(),
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -259,12 +259,12 @@
 
 Tine.Addressbook.ContactGridPanel.displayNameRenderer = function(data) {
     var i18n = Tine.Tinebase.appMgr.get('Addressbook').i18n;
-    return data ? data : ('<div class="renderer_displayNameRenderer_noName">' + i18n._('No name') + '</div>');
+    return data ? Ext.util.Format.htmlEncode(data) : ('<div class="renderer_displayNameRenderer_noName">' + i18n._('No name') + '</div>');
 };
 
 Tine.Addressbook.ContactGridPanel.countryRenderer = function(data) {
     data = Locale.getTranslationData('CountryList', data);
-    return data;
+    return Ext.util.Format.htmlEncode(data);
 };
 
 /**
```
