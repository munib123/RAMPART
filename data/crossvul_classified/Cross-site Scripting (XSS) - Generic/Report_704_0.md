# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 704_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `704_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 949-989 of the vulnerable file.

                    $img_source = 'icons/32/event.png';
                    break;
                default:
                    $img_source = 'icons/32/ticket.png';
                    break;
            }

            $row['start_date'] = Display::dateToStringAgoAndLongDate($row['start_date']);
            $row['sys_lastedit_datetime'] = Display::dateToStringAgoAndLongDate($row['sys_lastedit_datetime']);

            $icon = Display::return_icon(
                $img_source,
                get_lang('Info'),
                ['style' => 'margin-right: 10px; float: left;']
            );

            $icon .= '<a href="ticket_details.php?ticket_id='.$row['id'].'">'.$row['code'].'</a>';

            if ($isAdmin) {
                $ticket = [
                    $icon.' '.$row['subject'],
                    $row['status_name'],
                    $row['start_date'],
                    $row['sys_lastedit_datetime'],
                    $row['category_name'],
                    $name,
                    $row['assigned_last_user'],
                    $row['total_messages'],
                ];
            } else {
                $ticket = [
                    $icon.' '.$row['subject'],
                    $row['status_name'],
                    $row['start_date'],
                    $row['sys_lastedit_datetime'],
                    $row['category_name'],
                ];
            }
            if ($isAdmin) {
                $ticket['0'] .= '&nbsp;&nbsp;<a  href="javascript:void(0)" onclick="load_history_ticket(\'div_'.$row['ticket_id'].'\','.$row['ticket_id'].')">
					<img onclick="load_course_list(\'div_'.$row['ticket_id'].'\','.$row['ticket_id'].')" onmouseover="clear_course_list (\'div_'.$row['ticket_id'].'\')" src="'.Display::returnIconPath('history.gif').'" title="'.get_lang('Historial').'" alt="'.get_lang('Historial').'"/>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -966,7 +966,7 @@
 
             if ($isAdmin) {
                 $ticket = [
-                    $icon.' '.$row['subject'],
+                    $icon.' '.Security::remove_XSS($row['subject']),
                     $row['status_name'],
                     $row['start_date'],
                     $row['sys_lastedit_datetime'],
@@ -977,7 +977,7 @@
                 ];
             } else {
                 $ticket = [
-                    $icon.' '.$row['subject'],
+                    $icon.' '.Security::remove_XSS($row['subject']),
                     $row['status_name'],
                     $row['start_date'],
                     $row['sys_lastedit_datetime'],
```
