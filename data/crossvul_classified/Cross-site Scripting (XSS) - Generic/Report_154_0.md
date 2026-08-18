# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 154_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `154_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-22 of the vulnerable file.

<?php
	$mayModify = ($isSiteAdmin || ($isAclModify && $event['Event']['user_id'] == $me['id'] && $event['Orgc']['id'] == $me['org_id']) || ($isAclModifyOrg && $event['Orgc']['id'] == $me['org_id']));
	$mayPublish = ($isAclPublish && $event['Orgc']['id'] == $me['org_id']);
	$mayChangeCorrelation = !Configure::read('MISP.completely_disable_correlation') && ($isSiteAdmin || ($mayModify && Configure::read('MISP.allow_disabling_correlation')));
	$possibleAction = 'Proposal';
	if ($mayModify) $possibleAction = 'Attribute';
	$all = false;
	if (isset($this->params->params['paging']['Event']['page'])) {
		if ($this->params->params['paging']['Event']['page'] == 0) $all = true;
		$page = $this->params->params['paging']['Event']['page'];
	} else {
		$page = 0;
	}
	$fieldCount = 11;
	if (!empty($event['Sighting'])) {
		foreach ($sightingsData['data'] as $aid => $data) {
			$sightingsData['data'][$aid]['html'] = '';
			foreach ($data as $type => $typeData) {
				$name = (($type != 'expiration') ? Inflector::pluralize($type) : $type);
				$sightingsData['data'][$aid]['html'] .= '<span class=\'blue bold\'>' . ucfirst(h($name)) . '</span><br />';
				foreach ($typeData['orgs'] as $org => $orgData) {
					$extra = (($org == $me['Organisation']['name']) ? " class=	'bold'" : "");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,11 @@
 <?php
+	$urlHere = $this->here;
+	$urlHere = explode('/', $urlHere);
+	foreach ($urlHere as $k => $v) {
+		$urlHere[$k] = urlencode($v);
+	}
+	$urlHere = implode('/', $urlHere);
+	$urlHere = $baseurl . $urlHere;
 	$mayModify = ($isSiteAdmin || ($isAclModify && $event['Event']['user_id'] == $me['id'] && $event['Orgc']['id'] == $me['org_id']) || ($isAclModifyOrg && $event['Orgc']['id'] == $me['org_id']));
 	$mayPublish = ($isAclPublish && $event['Orgc']['id'] == $me['org_id']);
 	$mayChangeCorrelation = !Configure::read('MISP.completely_disable_correlation') && ($isSiteAdmin || ($mayModify && Configure::read('MISP.allow_disabling_correlation')));
@@ -138,7 +145,7 @@
 		<div id="filter_correlation" title="Only show correlating attributes" role="button" tabindex="0" aria-label="Only show correlating attributes" class="attribute_filter_text<?php if ($attributeFilter == 'correlation') echo '_active'; ?>" onClick="filterAttributes('correlation', '<?php echo h($event['Event']['id']); ?>');">Correlation</div>
 		<div id="filter_warning" title="Only show potentially false positive attributes" role="button" tabindex="0" aria-label="Only show potentially false positive attributes" class="attribute_filter_text<?php if ($attributeFilter == 'warning') echo '_active'; ?>" onClick="filterAttributes('warning', '<?php echo h($event['Event']['id']); ?>');">Warnings</div>
 		<?php if ($me['Role']['perm_sync'] || $event['Orgc']['id'] == $me['org_id']): ?>
-			<div id="filter_deleted" title="Include deleted attributes" role="button" tabindex="0" aria-label="Include deleted attributes" class="attribute_filter_text<?php if ($deleted) echo '_active'; ?>" onClick="toggleDeletedAttributes('<?php echo Router::url( $this->here, true );?>');">Include deleted attributes</div>
+			<div id="filter_deleted" title="Include deleted attributes" role="button" tabindex="0" aria-label="Include deleted attributes" class="attribute_filter_text<?php if ($deleted) echo '_active'; ?>" onClick="toggleDeletedAttributes('<?php echo $urlHere;?>');">Include deleted attributes</div>
 		<?php endif; ?>
 		<div id="show_context" title="Show attribute context fields" role="button" tabindex="0" aria-label="Show attribute context fields" class="attribute_filter_text" onClick="toggleContextFields();">Show context fields</div>
 		<div title="input filter" tabindex="0" aria-label="input filter" class="attribute_filter_text" style="padding-top:0px;">
@@ -168,7 +175,7 @@
 			?>
 					<th class="event_id"><?php echo $this->Paginator->sort('event_id', 'Event');?></th>
 			<?php
-		endif;
+				endif;
 			?>
 			<th><?php echo $this->Paginator->sort('Org.name', 'Org'); ?>
 			<th><?php echo $this->Paginator->sort('category');?></th>
```
