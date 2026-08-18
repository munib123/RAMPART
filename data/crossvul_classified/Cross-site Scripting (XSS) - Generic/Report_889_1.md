# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 889_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `889_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 10-43 of the vulnerable file.

                this.$widget.addClass('loading');

                var data = {
                    url: url,
                    limit: limit
                };

                Craft.postActionRequest('dashboard/get-feed-items', data, $.proxy(function(response, textStatus) {
                    this.$widget.removeClass('loading');

                    if (textStatus === 'success') {
                        this.$widget.find('table')
                            .attr('dir', response.dir);

                        var $tds = this.$widget.find('td');

                        for (var i = 0; i < response.items.length; i++) {
                            var item = response.items[i],
                                $td = $($tds[i]);

                            var widgetHtml = '<a href="' + item.permalink + '" target="_blank">' + item.title + '</a> ';

                            if (item.date) {
                                widgetHtml += '<span class="light nowrap">' + item.date + '</span>';
                            }

                            $td.html(widgetHtml);
                        }
                    }

                }, this));
            }
        });
})(jQuery);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -27,7 +27,11 @@
                             var item = response.items[i],
                                 $td = $($tds[i]);
 
-                            var widgetHtml = '<a href="' + item.permalink + '" target="_blank">' + item.title + '</a> ';
+                            var widgetHtml = $('<a/>', {
+                                href: item.permalink,
+                                target: '_blank',
+                                text: item.title
+                            }).html() + ' ';
 
                             if (item.date) {
                                 widgetHtml += '<span class="light nowrap">' + item.date + '</span>';
```
