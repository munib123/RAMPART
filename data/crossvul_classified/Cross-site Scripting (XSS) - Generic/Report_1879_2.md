# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1879_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1879_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 10-37 of the vulnerable file.

			$timeSettings = $this->getTimeSettings();
			$this->parameter = array(
				'idSite' => self::$wpPiwik->getPiwikSiteId($this->blogId),
				'period' => $timeSettings['period'],
				'date'  => $timeSettings['date']
			);
			$this->title = $prefix.__('Site Search', 'wp-piwik').' ('.__($timeSettings['description'],'wp-piwik').')';
			$this->method = 'Actions.getSiteSearchKeywords';
		}
		
		public function show() {
			$response = self::$wpPiwik->request($this->apiID[$this->method]);
			if (!empty($response['result']) && $response['result'] ='error')
				echo '<strong>'.__('Piwik error', 'wp-piwik').':</strong> '.htmlentities($response['message'], ENT_QUOTES, 'utf-8');
			else {
				$tableHead = array(__('Keyword', 'wp-piwik'), __('Requests', 'wp-piwik'), __('Bounced', 'wp-piwik'));
				$tableBody = array();
				$count = 0;
				foreach ($response as $row) {
					$count++;
					$tableBody[] = array($row['label'], $row['nb_visits'], $row['bounce_rate']);
					if ($count == 10) break;
				}
				$this->table($tableHead, $tableBody, null);
			}
		}
		
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -27,7 +27,7 @@
 				$count = 0;
 				foreach ($response as $row) {
 					$count++;
-					$tableBody[] = array($row['label'], $row['nb_visits'], $row['bounce_rate']);
+					$tableBody[] = array(htmlentities($row['label']), $row['nb_visits'], $row['bounce_rate']);
 					if ($count == 10) break;
 				}
 				$this->table($tableHead, $tableBody, null);
```
