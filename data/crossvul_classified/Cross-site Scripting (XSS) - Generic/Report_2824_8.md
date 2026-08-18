# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 2824_8
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2824_8`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 503-543 of the vulnerable file.

            
            // add implicit / ignored fields (important e.g. for container_id)
            Ext.each(this.criteriaIgnores, function(criteria) {
                if (criteria.field != this.quickFilterField) {
                    var filterIdx = this.activeFilterPanel.filterStore.find('field', criteria.field),
                        filter = filterIdx >= 0  ? this.activeFilterPanel.filterStore.getAt(filterIdx) : null,
                        filterModel = filter ? this.activeFilterPanel.getFilterModel(filter) : null;
                    
                    if (filter) {
                        filters.push(Ext.isFunction(filterModel.getFilterData) ? filterModel.getFilterData(filter) : this.activeFilterPanel.getFilterData(filter));
                    }
                }
                
            }, this);
            
            return filters;
        }
        
        for (var id in this.filterPanels) {
            if (this.filterPanels.hasOwnProperty(id) && this.filterPanels[id].isActive) {
                filters.push({'condition': 'AND', 'filters': this.filterPanels[id].getValue(), 'id': id, label: this.filterPanels[id].title});
            }
        }
        
        // NOTE: always trigger a OR condition, otherwise we sould loose inactive FilterPanles
        //return filters.length == 1 ? filters[0].filters : [{'condition': 'OR', 'filters': filters}];
        return [{'condition': 'OR', 'filters': filters}];
    },
    
    setValue: function(value) {
        // save last filter ?
        var prefs;
        if ((prefs = this.filterToolbarConfig.app.getRegistry().get('preferences')) && prefs.get('defaultpersistentfilter') == '_lastusedfilter_') {
            var lastFilterStateName = this.filterToolbarConfig.recordClass.getMeta('appName') + '-' + this.filterToolbarConfig.recordClass.getMeta('recordName') + '-lastusedfilter';
            
            if (Ext.encode(Ext.state.Manager.get(lastFilterStateName)) != Ext.encode(value)) {
                Tine.log.debug('Tine.widgets.grid.FilterPanel::setValue save last used filter');
                Ext.state.Manager.set(lastFilterStateName, value);
            }
        }
        
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -520,7 +520,7 @@
         
         for (var id in this.filterPanels) {
             if (this.filterPanels.hasOwnProperty(id) && this.filterPanels[id].isActive) {
-                filters.push({'condition': 'AND', 'filters': this.filterPanels[id].getValue(), 'id': id, label: this.filterPanels[id].title});
+                filters.push({'condition': 'AND', 'filters': this.filterPanels[id].getValue(), 'id': id, label: Ext.util.Format.htmlDecode(this.filterPanels[id].title)});
             }
         }
         
```
