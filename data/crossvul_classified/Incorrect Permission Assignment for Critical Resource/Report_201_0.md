# CrossVul Fix Pair: Incorrect Permission Assignment for Critical Resource in php
**Pair ID:** 201_0
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-732
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `201_0`)

## Vulnerability Information & PoC

## Description
Incorrect Permission Assignment for Critical Resource - When a resource is given a permission setting that provides access to a wider range of actors than required, it could lead to the exposure of sensitive information, or the modification of that reso...

## Vulnerable Code
```php
Lines 221-261 of the vulnerable file.

					$notmorethanxopentickets = strtr($lng['ticket']['notmorethanxopentickets'], array('%s' => Settings::Get('ticket.concurrently_open')));
				} else {
					$notmorethanxopentickets = '';
				}

				$ticketsopen = (int)$opentickets['count'];

				$ticket_add_data = include_once dirname(__FILE__).'/lib/formfields/customer/tickets/formfield.ticket_add.php';
				$ticket_add_form = htmlform::genHTMLForm($ticket_add_data);

				$title = $ticket_add_data['ticket_add']['title'];
				$image = $ticket_add_data['ticket_add']['image'];

				eval("echo \"" . getTemplate("tickets/tickets_new") . "\";");
			}
		} else {
			standard_error('nomoreticketsavailable');
		}
	} elseif ($action == 'answer' && $id != 0) {
		if (isset($_POST['send']) && $_POST['send'] == 'send') {
			$replyticket = ticket::getInstanceOf($userinfo, -1);
			$replyticket->Set('subject', validate($_POST['subject'], 'subject'), true, false);
			$replyticket->Set('priority', validate($_POST['priority'], 'priority'), true, false);
			$replyticket->Set('message', validate(str_replace("\r\n", "\n", $_POST['message']), 'message', '/^[^\0]*$/'), true, false);

			if ($replyticket->Get('message') == null) {
				standard_error(array('stringisempty', 'mymessage'));
			} else {
				$now = time();
				$replyticket->Set('customer', (int)$userinfo['customerid'], true, true);
				$replyticket->Set('lastchange', $now, true, true);
				$replyticket->Set('ip', $_SERVER['REMOTE_ADDR'], true, true);
				$replyticket->Set('status', '1', true, true);
				$replyticket->Set('answerto', (int)$id, true, false);
				$replyticket->Set('by', '0', true, true);
				$replyticket->Insert();

				// Update priority if changed
				$mainticket = ticket::getInstanceOf($userinfo, (int)$id);

				if ($replyticket->Get('priority') != $mainticket->Get('priority')) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -238,7 +238,11 @@
 		}
 	} elseif ($action == 'answer' && $id != 0) {
 		if (isset($_POST['send']) && $_POST['send'] == 'send') {
-			$replyticket = ticket::getInstanceOf($userinfo, -1);
+			try {
+				$replyticket = ticket::getInstanceOf($userinfo, -1);
+			} catch(Exception $e) {
+				standard_error($e->getMessage());
+			}
 			$replyticket->Set('subject', validate($_POST['subject'], 'subject'), true, false);
 			$replyticket->Set('priority', validate($_POST['priority'], 'priority'), true, false);
 			$replyticket->Set('message', validate(str_replace("\r\n", "\n", $_POST['message']), 'message', '/^[^\0]*$/'), true, false);
@@ -272,7 +276,11 @@
 			}
 		} else {
 			$ticket_replies = '';
-			$mainticket = ticket::getInstanceOf($userinfo, (int)$id);
+			try {
+				$mainticket = ticket::getInstanceOf($userinfo, (int)$id);
+			} catch(Exception $e) {
+				standard_error($e->getMessage());
+			}
 			$dt = date("d.m.Y H:i\h", $mainticket->Get('dt'));
 			$status = ticket::getStatusText($lng, $mainticket->Get('status'));
 
@@ -351,7 +359,11 @@
 	} elseif ($action == 'close' && $id != 0) {
 		if (isset($_POST['send']) && $_POST['send'] == 'send') {
 			$now = time();
-			$mainticket = ticket::getInstanceOf($userinfo, (int)$id);
+			try {
+				$mainticket = ticket::getInstanceOf($userinfo, (int)$id);
+			} catch(Exception $e) {
+				standard_error($e->getMessage());
+			}
 			$mainticket->Set('lastchange', $now, true, true);
 			$mainticket->Set('lastreplier', '0', true, true);
 			$mainticket->Set('status', '3', true, true);
@@ -359,7 +371,11 @@
 			$log->logAction(USR_ACTION, LOG_NOTICE, "closed support-ticket '" . $mainticket->Get('subject') . "'");
 			redirectTo($filename, array('page' => $page, 's' => $s));
 		} else {
-			$mainticket = ticket::getInstanceOf($userinfo, (int)$id);
+			try {
+				$mainticket = ticket::getInstanceOf($userinfo, (int)$id);
+			} catch(Exception $e) {
+				standard_error($e->getMessage());
+			}
 			ask_yesno('ticket_reallyclose', $filename, array('id' => $id, 'page' => $page, 'action' => $action), $mainticket->Get('subject'));
 		}
 	} elseif ($action == 'reopen' && $id != 0) {
@@ -377,7 +393,11 @@
 		}
 
 		$now = time();
-		$mainticket = ticket::getInstanceOf($userinfo, (int)$id);
+		try {
+			$mainticket = ticket::getInstanceOf($userinfo, (int)$id);
+		} catch(Exception $e) {
+			standard_error($e->getMessage());
+		}
 		$mainticket->Set('lastchange', $now, true, true);
 		$mainticket->Set('lastreplier', '0', true, true);
 		$mainticket->Set('status', '0', true, true);
```
