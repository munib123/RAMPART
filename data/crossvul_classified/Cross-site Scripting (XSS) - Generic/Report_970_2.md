# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 970_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `970_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 113-153 of the vulnerable file.

        deleteLink: function (id) {
            if (id == this.primaryId) {
                this.setPrimaryId(null);
            }
            Dep.prototype.deleteLink.call(this, id);
        },

        deleteLinkHtml: function (id) {
            Dep.prototype.deleteLinkHtml.call(this, id);
            this.managePrimaryButton();
        },

        addLinkHtml: function (id, name) {
            if (this.mode == 'search') {
                return Dep.prototype.addLinkHtml.call(this, id, name);
            }

            var $container = this.$el.find('.link-container');
            var $el = $('<div class="form-inline list-group-item link-with-role clearfix link-group-item-with-primary">').addClass('link-' + id).attr('data-id', id);

            var nameHtml = '<div>' + name + '&nbsp;' + '</div>';
            var removeHtml = '<a href="javascript:" class="pull-right" data-id="' + id + '" data-action="clearLink"><span class="fas fa-times"></a>';

            $left = $('<div>');
            $left.append(nameHtml);
            $el.append($left);

            $right = $('<div>');
            $right.append(removeHtml);
            $el.append($right);

            var isPrimary = (id == this.primaryId);
            var iconHtml = '<span class="fas fa-star fa-sm ' + (!isPrimary ? 'text-muted' : '') + '"></span>';
            var title = this.translate('Primary');
            var $primary = $('<button type="button" class="btn btn-link btn-sm pull-right hidden" title="'+title+'" data-action="switchPrimary" data-id="'+id+'">'+iconHtml+'</button>');
            $primary.insertBefore($el.children().first().children().first());

            $container.append($el);

            this.managePrimaryButton();

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -130,7 +130,7 @@
             var $container = this.$el.find('.link-container');
             var $el = $('<div class="form-inline list-group-item link-with-role clearfix link-group-item-with-primary">').addClass('link-' + id).attr('data-id', id);
 
-            var nameHtml = '<div>' + name + '&nbsp;' + '</div>';
+            var nameHtml = '<div>' + this.getHelper().escapeString(name) + '&nbsp;' + '</div>';
             var removeHtml = '<a href="javascript:" class="pull-right" data-id="' + id + '" data-action="clearLink"><span class="fas fa-times"></a>';
 
             $left = $('<div>');
```
