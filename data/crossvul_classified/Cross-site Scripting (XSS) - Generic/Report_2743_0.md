# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2743_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2743_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-19 of the vulnerable file.

<?php
App::uses('AppHelper', 'View/Helper');

//this helper simply replaces quotes between [QUOTE][/QUOTE] with div tags.
// And now [thread][/thread], [event][/event], [link][/link], [code][/code]


	class CommandHelper extends AppHelper {
		public function convertQuotes($string) {
			$string = str_ireplace('[QUOTE]', '<div class="quote">', $string);
			$string = str_ireplace('[/QUOTE]', '</div>', $string);
			$string = preg_replace('%\[event\]\s*(\d*)\s*\[/event\]%isU', '<a href="' . h(Configure::read('MISP.baseurl')). '/events/view/$1> Event $1</a>', $string);
			$string = preg_replace('%\[thread\]\s*(\d*)\s*\[/thread\]%isU', '<a href="' . h(Configure::read('MISP.baseurl')). '/threads/view/$1> Thread $1</a>', $string);
			$string = preg_replace('%\[link\]\s*(http|https|ftp|git|ftps)(.*)\s*\[/link\]%isU', '<a href="$1$2">$1$2</a>', $string);
			$string = preg_replace('%\[code\](.*)\[/code\]%isU', '<pre>$1</pre>', $string);

			return $string;
		}
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6,14 +6,88 @@
 
 
 	class CommandHelper extends AppHelper {
+		var $helpers = array('Html');
+
+		private $__replacement;
+
+		private function __buildReplacements() {
+			$this->__replacement = array(
+				'link' => array('type' => 'url', 'url' => '$1', 'text' => '$1'),
+				'thread' => array('type' => 'url', 'url' => h(Configure::read('MISP.baseurl')). '/threads/view/$1', 'text' => ' Thread $1'),
+				'event' => array('type' => 'url', 'url' => h(Configure::read('MISP.baseurl')). '/events/view/$1', 'text' => ' Event $1'),
+				'code' => array('type' => 'replace', 'text' => '<pre>$1</pre>'),
+				'quote' => array('type' => 'replace', 'text' => '<div class="quote">$1</div>')
+			);
+		}
+
+
 		public function convertQuotes($string) {
-			$string = str_ireplace('[QUOTE]', '<div class="quote">', $string);
-			$string = str_ireplace('[/QUOTE]', '</div>', $string);
-			$string = preg_replace('%\[event\]\s*(\d*)\s*\[/event\]%isU', '<a href="' . h(Configure::read('MISP.baseurl')). '/events/view/$1> Event $1</a>', $string);
-			$string = preg_replace('%\[thread\]\s*(\d*)\s*\[/thread\]%isU', '<a href="' . h(Configure::read('MISP.baseurl')). '/threads/view/$1> Thread $1</a>', $string);
-			$string = preg_replace('%\[link\]\s*(http|https|ftp|git|ftps)(.*)\s*\[/link\]%isU', '<a href="$1$2">$1$2</a>', $string);
-			$string = preg_replace('%\[code\](.*)\[/code\]%isU', '<pre>$1</pre>', $string);
-
+			$this->__buildReplacements();
+			foreach ($this->__replacement as $trigger => $replacement) {
+				$result = $this->__handleLinks($string, $trigger);
+				if (!$result) return 'Malformed syntax.';
+			}
 			return $string;
 		}
+
+		private function __handleLinks(&$string, $trigger) {
+			$opening = preg_match('%\[' . $trigger . '\]%isU', $string, $opening_matches, PREG_OFFSET_CAPTURE);
+			$closing = preg_match('%\[/' . $trigger . '\]%isU', $string, $closing_matches, PREG_OFFSET_CAPTURE);
+			$opening_len = strlen($trigger) + 2;
+			$closing_len = $opening_len + 1;
+			if ((count($opening) !== count($closing))) return false;
+			$pairs = array();
+			$rearrangedTags = array();
+			foreach ($opening_matches as $opening_tag) {
+				$rearrangedTags[$opening_tag[1]] = 'open';
+			}
+			foreach ($closing_matches as $closing_tag) {
+				$rearrangedTags[$closing_tag[1]] = 'close';
+			}
+			foreach ($opening_matches as $opening_tag) {
+				$counter = 1;
+				foreach ($rearrangedTags as $pos => $type) {
+					if ($opening_tag[1] == $pos) continue;
+					if ($type == 'close') $counter--;
+					else $counter++;
+					if ($counter == 0) {
+						$pairs[] = array($opening_tag[1], $pos);
+						continue 2;
+					}
+				}
+			}
+			foreach ($pairs as $pair) {
+				$temp = substr($string, 0, $pair[0]);
+				if ($this->__replacement[$trigger]['type'] == 'url') {
+					$data = substr($string, $pair[0] + $opening_len, $pair[1] - ($pair[0] + $opening_len));
+					if (empty($data)) {
+						$replacement = '';
+					} else {
+						if (!is_numeric($data) && ($trigger == 'event' || $trigger == 'thread')) {
+							$replacement = '%MALFORMED URL%';
+						} else {
+							if (filter_var(str_replace('$1', $data, $this->__replacement[$trigger]['url']), FILTER_VALIDATE_URL)) {
+								$replacement = $this->Html->link(
+									str_replace('$1', $data, $this->__replacement[$trigger]['text']),
+									str_replace('$1', $data, $this->__replacement[$trigger]['url'])
+								);
+							} else {
+								$replacement = '%MALFORMED URL%';
+							}
+						}
+					}
+				} else {
+					$data = substr($string, $pair[0] + $opening_len, $pair[1] - ($pair[0] + $opening_len));
+					if (empty($data)) {
+						$replacement = '';
+					} else {
+						$replacement = str_replace('$1', $data, $this->__replacement[$trigger]['text']);
+					}
+				}
+				$temp .= $replacement;
+				$temp .= substr($string, $pair[1] + $closing_len, strlen($string));
+				$string = $temp;
+			}
+			return true;
+		}
 	}
```
