# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 970_7
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `970_7`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 24-64 of the vulnerable file.

 *
 * In accordance with Section 7(b) of the GNU General Public License version 3,
 * these Appropriate Legal Notices must retain the display of the "EspoCRM" word.
 ************************************************************************/

Espo.define('views/site/navbar', 'view', function (Dep) {

    return Dep.extend({

        template: 'site/navbar',

        currentTab: null,

        data: function () {
            return {
                tabDefsList: this.tabDefsList,
                title: this.options.title,
                menuDataList: this.getMenuDataList(),
                quickCreateList: this.quickCreateList,
                enableQuickCreate: this.quickCreateList.length > 0,
                userName: this.getUser().get('name'),
                userId: this.getUser().id,
                logoSrc: this.getLogoSrc()
            };
        },

        events: {
            'click .navbar-collapse.in a.nav-link': function (e) {
                var $a = $(e.currentTarget);
                var href = $a.attr('href');
                if (href) {
                    this.$el.find('.navbar-collapse.in').collapse('hide');
                }
            },
            'click a.nav-link': function (e) {
                if (this.isSideMenuOpened) {
                    this.closeSideMenu();
                }
            },
            'click a.navbar-brand.nav-link': function (e) {
                this.$el.find('.navbar-collapse.in').collapse('hide');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -41,7 +41,6 @@
                 menuDataList: this.getMenuDataList(),
                 quickCreateList: this.quickCreateList,
                 enableQuickCreate: this.quickCreateList.length > 0,
-                userName: this.getUser().get('name'),
                 userId: this.getUser().id,
                 logoSrc: this.getLogoSrc()
             };
@@ -528,7 +527,7 @@
             var list = [
                 {
                     link: '#User/view/' + this.getUser().id,
-                    html: avatarHtml + this.getUser().get('name')
+                    html: avatarHtml + this.getHelper().escapeString(this.getUser().get('name')),
                 },
                 {divider: true}
             ];
```
