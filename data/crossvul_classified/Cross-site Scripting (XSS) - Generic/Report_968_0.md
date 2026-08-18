# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 968_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `968_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 2166-2206 of the vulnerable file.

    }
});

$(document).on("keyup", function(evt) {
    switch(evt.keyCode) {
        case 16: // <SHIFT>
        if (!user_manipulation) { // user can't modify references
        break;
    }
    eventGraph.network.disableEditMode(); // un-toggle edit mode
    break;
    default:
    break;
}
});

eventGraph.update_scope();
dataHandler.fetch_data_and_update(true, function() {
    var $select = $('#network-typeahead');
    dataHandler.get_typeaheadData_search().forEach(function(element) {
        $select.append('<option value="' + element + '">' + element + '</option>');
    });
    $('#network-typeahead').chosen(chosen_options).on('change', function(evt, params) {
        var value = params.selected;
        var nodeID = dataHandler.mapping_value_to_nodeID.get(value);
        // in case we searched for an object relation
        nodeID = nodeID === undefined ? dataHandler.mapping_obj_relation_value_to_nodeID.get(value) : nodeID;
        // check if node in cluster
        nested_length = eventGraph.network.findNode(nodeID).length;
        if (nested_length > 1) { // Node is in cluster
            // As vis.js cannot supply a way to uncluster a single node, we remove it and add it again
            searched_node = eventGraph.nodes.get(nodeID);
            // Remove old node and edges
            eventGraph.nodes.remove(nodeID);
            eventGraph.nodes.add(searched_node);
            /* don't need to re-add the edge as it is the same */
            eventGraph.focus_on_stabilized(nodeID);
        } else {
            // set focus to the network
            eventGraph.network.focus(nodeID, {animation: true, scale: 1});
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2183,7 +2183,10 @@
 dataHandler.fetch_data_and_update(true, function() {
     var $select = $('#network-typeahead');
     dataHandler.get_typeaheadData_search().forEach(function(element) {
-        $select.append('<option value="' + element + '">' + element + '</option>');
+        var $option = $('<option></option>');
+        $option.text(element);
+        $option.attr('value', $option.text());
+        $select.append($option);
     });
     $('#network-typeahead').chosen(chosen_options).on('change', function(evt, params) {
         var value = params.selected;
```
