# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1971_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1971_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 41-81 of the vulnerable file.

    $table_data[] = array('key' => __('Name'), 'value' => $cluster['GalaxyCluster']['value']);
    $table_data[] = array('key' => __('Parent Galaxy'), 'value' => $cluster['GalaxyCluster']['Galaxy']['name'] ? $cluster['GalaxyCluster']['Galaxy']['name'] : $cluster['GalaxyCluster']['Galaxy']['type']);
    $table_data[] = array('key' => __('Description'), 'value' => $cluster['GalaxyCluster']['description']);
    $table_data[] = array('key' => __('Published'), 'boolean' => $cluster['GalaxyCluster']['published'], 'class' => (!$cluster['GalaxyCluster']['published'] ? 'background-red bold': ''));
    $table_data[] = array('key' => __('Default'), 'boolean' => $cluster['GalaxyCluster']['default'], 'class' => (!$cluster['GalaxyCluster']['published'] ? 'black': 'black'));
    $table_data[] = array('key' => __('Version'), 'value' => $cluster['GalaxyCluster']['version']);
    $table_data[] = array('key' => __('UUID'), 'value' => $cluster['GalaxyCluster']['uuid'], 'value_class' => 'quickSelect');
    $table_data[] = array('key' => __('Collection UUID'), 'value' => $cluster['GalaxyCluster']['collection_uuid'], 'value_class' => 'quickSelect');
    $table_data[] = array(
        'key' => __('Source'),
        'html' => filter_var($cluster['GalaxyCluster']['source'], FILTER_VALIDATE_URL) ?
            '<a href="' . $cluster['GalaxyCluster']['source'] . '" rel="noreferrer noopener">' . h($cluster['GalaxyCluster']['source']) :
            h($cluster['GalaxyCluster']['source']),
    );
    $table_data[] = array('key' => __('Authors'), 'value' => !empty($cluster['GalaxyCluster']['authors']) ? implode(', ', $cluster['GalaxyCluster']['authors']) : __('N/A'));
    $table_data[] = array('key' => __('Distribution'), 'element' => 'genericElements/IndexTable/Fields/distribution_levels', 'element_params' => array(
        'row' => $cluster['GalaxyCluster'],
        'field' => array('data_path' => 'distribution')
    ));
    $table_data[] = array(
        'key' => __('Owner Organisation'), 
        'html' => $this->OrgImg->getOrgImg(array('name' => $cluster['GalaxyCluster']['Org']['name'], 'id' => $cluster['GalaxyCluster']['Org']['id'], 'size' => 18), true),
    );
    $table_data[] = array(
        'key' => __('Creator Organisation'), 
        'html' => $this->OrgImg->getOrgImg(array('name' => $cluster['GalaxyCluster']['Orgc']['name'], 'id' => $cluster['GalaxyCluster']['Orgc']['id'], 'size' => 18), true),
    );
    $table_data[] = array('key' => __('Connector tag'), 'value' => $cluster['GalaxyCluster']['tag_name']);
    $table_data[] = array('key' => __('Events'), 'html' => isset($cluster['GalaxyCluster']['tag_count']) ? 
                        sprintf('<a href="%s">%s</a>',
                            sprintf('%s/events/index/searchtag:%s', $baseurl, h($cluster['GalaxyCluster']['tag_id'])),
                            __n('%s event', '%s events', $cluster['GalaxyCluster']['tag_count'], h($cluster['GalaxyCluster']['tag_count']))
                        ):
                        '0'
                    );
    if (!empty($extendedFromHtml)) {
        $table_data[] = array('key' => __('Forked From'), 'html' => $extendedFromHtml);
    }
    if (!empty($extendedByHtml)) {
        $table_data[] = array('key' => __('Forked By'), 'html' => $extendedByHtml);
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -58,15 +58,15 @@
         'field' => array('data_path' => 'distribution')
     ));
     $table_data[] = array(
-        'key' => __('Owner Organisation'), 
+        'key' => __('Owner Organisation'),
         'html' => $this->OrgImg->getOrgImg(array('name' => $cluster['GalaxyCluster']['Org']['name'], 'id' => $cluster['GalaxyCluster']['Org']['id'], 'size' => 18), true),
     );
     $table_data[] = array(
-        'key' => __('Creator Organisation'), 
+        'key' => __('Creator Organisation'),
         'html' => $this->OrgImg->getOrgImg(array('name' => $cluster['GalaxyCluster']['Orgc']['name'], 'id' => $cluster['GalaxyCluster']['Orgc']['id'], 'size' => 18), true),
     );
     $table_data[] = array('key' => __('Connector tag'), 'value' => $cluster['GalaxyCluster']['tag_name']);
-    $table_data[] = array('key' => __('Events'), 'html' => isset($cluster['GalaxyCluster']['tag_count']) ? 
+    $table_data[] = array('key' => __('Events'), 'html' => isset($cluster['GalaxyCluster']['tag_count']) ?
                         sprintf('<a href="%s">%s</a>',
                             sprintf('%s/events/index/searchtag:%s', $baseurl, h($cluster['GalaxyCluster']['tag_id'])),
                             __n('%s event', '%s events', $cluster['GalaxyCluster']['tag_count'], h($cluster['GalaxyCluster']['tag_count']))
@@ -85,7 +85,7 @@
     <div class="row-fluid">
         <div class="span8">
             <h2>
-                <?= sprintf('%s :: %s', h($cluster['GalaxyCluster']['Galaxy']['name']), $cluster['GalaxyCluster']['value']); ?>
+                <?= sprintf('%s :: %s', h($cluster['GalaxyCluster']['Galaxy']['name']), h($cluster['GalaxyCluster']['value'])); ?>
             </h2>
             <?php echo $this->element('genericElements/viewMetaTable', array('table_data' => $table_data)); ?>
         </div>
```
