# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in php
**Pair ID:** 3981_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3981_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```php
Lines 255-295 of the vulnerable file.

		$start = microtime(true);
		$CI = get_instance();

		$discovery_id = $queue_item->discovery_id;

		$item = $CI->m_discoveries->read($discovery_id);
		$discovery = $item[0];

		$log = new stdClass();
		$log->discovery_id = $discovery_id;
		$log->command_status = 'start';
		$log->message = 'Starting discovery for ' . $discovery->attributes->name;
		$log->ip = '127.0.0.1';
		$log->severity = 6;
		discovery_log($log);

		$sql = '/* discoveries_helper::discover_subnet */ ' . "UPDATE `discoveries` SET `status` = 'running', `ip_all_count` = 0, `ip_responding_count` = 0, `ip_scanned_count` = 0, `ip_discovered_count` = 0, `ip_audited_count` = 0, `last_run` = NOW() WHERE id = ?";
		$data = array($discovery_id);
		$CI->db->query($sql, $data);

		if ( ! empty($CI->config->config['discovery_ip_exclude'])) {
			// Account for users adding multiple spaces which would be converted to multiple comma's.
			$exclude_ip = preg_replace('!\s+!', ' ', $CI->config->config['discovery_ip_exclude']);
			// Convert spaces to comma's
			$exclude_ip = str_replace(' ', ',', $exclude_ip);
			if ( ! empty($discovery->attributes->other->nmap->exclude_ip)) {
				$discovery->attributes->other->nmap->exclude_ip .= ',' . $exclude_ip;
			} else {
				$discovery->attributes->other->nmap->exclude_ip = $exclude_ip;
			}
		}

		$all_ip_list = all_ip_list($discovery);

		$count = @count($all_ip_list);
		$log->command_status = 'notice';
		$log->message = 'Ping response not required, assuming all ' . $count . ' IP addresses are up.';
		if ($discovery->attributes->other->nmap->ping === 'y') {
			$log->message = 'Scanning ' . $count . ' IP addresses using Nmap to test for response.';
		}
		discovery_log($log);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -272,6 +272,13 @@
 		$data = array($discovery_id);
 		$CI->db->query($sql, $data);
 
+		if ( ! preg_match('/^[\d,\.,\/,\-]*$/', $discovery->attributes->other->subnet)) {
+			$log->message = 'Invalid subnet value supplied of ' . htmlentities($discovery->attributes->other->subnet);
+			$log->severity = 5;
+			discovery_log($log);
+			return;
+		}
+
 		if ( ! empty($CI->config->config['discovery_ip_exclude'])) {
 			// Account for users adding multiple spaces which would be converted to multiple comma's.
 			$exclude_ip = preg_replace('!\s+!', ' ', $CI->config->config['discovery_ip_exclude']);
@@ -282,6 +289,13 @@
 			} else {
 				$discovery->attributes->other->nmap->exclude_ip = $exclude_ip;
 			}
+		}
+		// Ensure we only have valid characters of digit, dot, slash and comma in attribute
+		if ( ! preg_match('/^[\d,\.,\/,\-,\,]*$/', $discovery->attributes->other->nmap->exclude_ip)) {
+			$discovery->attributes->other->nmap->exclude_ip = '';
+			$log->message = 'Invalid characters supplied in exclude_ip, setting to blank.';
+			$log->severity = 5;
+			discovery_log($log);
 		}
 
 		$all_ip_list = all_ip_list($discovery);
```
