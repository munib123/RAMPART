# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2149_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2149_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 317-357 of the vulnerable file.

if ($user->url && !isset($hiddenfields['webpage'])) {
    $url = $user->url;
    if (strpos($user->url, '://') === false) {
        $url = 'http://'. $url;
    }
    $webpageurl = new moodle_url($url);
    echo html_writer::tag('dt', get_string('webpage'));
    echo html_writer::tag('dd', html_writer::link($webpageurl, s($user->url)));
}

if ($user->icq && !isset($hiddenfields['icqnumber'])) {
    $imurl = new moodle_url('http://web.icq.com/wwp', array('uin' => $user->icq) );
    $iconurl = new moodle_url('http://web.icq.com/whitepages/online', array('icq' => $user->icq, 'img' => '5'));
    $statusicon = html_writer::tag('img', '', array('src' => $iconurl, 'class' => 'icon icon-post', 'alt' => get_string('status')));
    echo html_writer::tag('dt', get_string('icqnumber'));
    echo html_writer::tag('dd', html_writer::link($imurl, s($user->icq) . $statusicon));
}

if ($user->skype && !isset($hiddenfields['skypeid'])) {
    $imurl = 'skype:'.urlencode($user->skype).'?call';
    $iconurl = new moodle_url('http://mystatus.skype.com/smallicon/'.$user->skype);
    if (strpos($CFG->httpswwwroot, 'https:') === 0) {
        // Bad luck, skype devs are lazy to set up SSL on their servers - see MDL-37233.
        $statusicon = '';
    } else {
        $statusicon = html_writer::empty_tag('img',
            array('src' => $iconurl, 'class' => 'icon icon-post', 'alt' => get_string('status')));
    }
    echo html_writer::tag('dt', get_string('skypeid'));
    echo html_writer::tag('dd', html_writer::link($imurl, s($user->skype) . $statusicon));
}
if ($user->yahoo && !isset($hiddenfields['yahooid'])) {
    $imurl = new moodle_url('http://edit.yahoo.com/config/send_webmesg', array('.target' => $user->yahoo, '.src' => 'pg'));
    $iconurl = new moodle_url('http://opi.yahoo.com/online', array('u' => $user->yahoo, 'm' => 'g', 't' => '0'));
    $statusicon = html_writer::tag('img', '',
        array('src' => $iconurl, 'class' => 'iconsmall icon-post', 'alt' => get_string('status')));
    echo html_writer::tag('dt', get_string('yahooid'));
    echo html_writer::tag('dd', html_writer::link($imurl, s($user->yahoo) . $statusicon));
}
if ($user->aim && !isset($hiddenfields['aimid'])) {
    $imurl = 'aim:goim?screenname='.urlencode($user->aim);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -334,7 +334,7 @@
 
 if ($user->skype && !isset($hiddenfields['skypeid'])) {
     $imurl = 'skype:'.urlencode($user->skype).'?call';
-    $iconurl = new moodle_url('http://mystatus.skype.com/smallicon/'.$user->skype);
+    $iconurl = new moodle_url('http://mystatus.skype.com/smallicon/'.urlencode($user->skype));
     if (strpos($CFG->httpswwwroot, 'https:') === 0) {
         // Bad luck, skype devs are lazy to set up SSL on their servers - see MDL-37233.
         $statusicon = '';
```
