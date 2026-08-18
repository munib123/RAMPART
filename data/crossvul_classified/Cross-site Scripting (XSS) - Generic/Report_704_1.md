# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 704_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `704_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 169-209 of the vulnerable file.

    } else {
        $userGroup = new UserGroup();
        $group_info = $userGroup->get($group_id);

        $form->addElement('label', get_lang('ToGroup'), api_xml_http_response_encode($group_info['name']));
        $form->addElement('hidden', 'group_id', $group_id);
        $form->addElement('hidden', 'parent_id', $message_id);
    }

    $form->addText('title', get_lang('Subject'), true);
    $form->addHtmlEditor(
        'content',
        get_lang('Message'),
        false,
        false,
        ['ToolbarSet' => 'Messages', 'Width' => '100%', 'Height' => '250']
    );

    if (isset($_GET['re_id'])) {
        $message_reply_info = MessageManager::get_message_by_id($_GET['re_id']);
        $default['title'] = get_lang('MailSubjectReplyShort').' '.$message_reply_info['title'];
        $form->addHidden('re_id', (int) $_GET['re_id']);
        $form->addHidden('save_form', 'save_form');

        // Adding reply mail
        $user_reply_info = api_get_user_info($message_reply_info['user_sender_id']);
        $default['content'] = '<p><br/></p>'.sprintf(
            get_lang('XWroteY'),
            $user_reply_info['complete_name'],
            Security::filter_terms($message_reply_info['content'])
        );
    }

    if (isset($_GET['forward_id'])) {
        $forwardId = (int) $_GET['forward_id'];
        $message_reply_info = MessageManager::get_message_by_id($forwardId);
        $attachments = MessageManager::getAttachmentLinkList($forwardId);
        if (!empty($attachments)) {
            $fileListToString = !empty($attachments) ? implode('<br />', $attachments) : '';
            $form->addLabel('', $fileListToString);
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -186,7 +186,7 @@
 
     if (isset($_GET['re_id'])) {
         $message_reply_info = MessageManager::get_message_by_id($_GET['re_id']);
-        $default['title'] = get_lang('MailSubjectReplyShort').' '.$message_reply_info['title'];
+        $default['title'] = get_lang('MailSubjectReplyShort').' '.Security::remove_XSS($message_reply_info['title']);
         $form->addHidden('re_id', (int) $_GET['re_id']);
         $form->addHidden('save_form', 'save_form');
 
@@ -207,14 +207,14 @@
             $fileListToString = !empty($attachments) ? implode('<br />', $attachments) : '';
             $form->addLabel('', $fileListToString);
         }
-        $default['title'] = '['.get_lang('MailSubjectForwardShort').": ".$message_reply_info['title'].']';
+        $default['title'] = '['.get_lang('MailSubjectForwardShort').": ".Security::remove_XSS($message_reply_info['title']).']';
         $form->addHidden('forward_id', $forwardId);
         $form->addHidden('save_form', 'save_form');
         $receiverInfo = api_get_user_info($message_reply_info['user_receiver_id']);
 
         $forwardMessage = '---------- '.get_lang('ForwardedMessage').' ---------'.'<br />';
         $forwardMessage .= get_lang('Date').': '.api_get_local_time($message_reply_info['send_date']).'<br />';
-        $forwardMessage .= get_lang('Subject').': '.$message_reply_info['title'].'<br />';
+        $forwardMessage .= get_lang('Subject').': '.Security::remove_XSS($message_reply_info['title']).'<br />';
         $forwardMessage .= get_lang('To').': '.$receiverInfo['complete_name'].' - '.$receiverInfo['email'].' <br />';
         $default['content'] = '<p><br/></p>'.$forwardMessage.'<br />'.Security::filter_terms($message_reply_info['content']);
     }
```
