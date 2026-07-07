# HackerOne Report: full path disclosure from false language
**Report ID:** 13237
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
https://www.localize.im/projects/3t/languages/4xX

 Fatal error: Uncaught exception 'Exception' with message 'Unknown language ID 3083' in /srv/data/web/vhosts/www.localize.im/htdocs/classes/Language.php:423 Stack trace: #0 /srv/data/web/vhosts/www.localize.im/htdocs/classes/Language.php(221): Language::getLanguageName(3083) #1 /srv/data/web/vhosts/www.localize.im/htdocs/classes/Language.php(217): Language::getLanguageNameFull(3083) #2 /srv/data/web/vhosts/www.localize.im/htdocs/classes/UI.php(1375): Language->getNameFull() #3 /srv/data/web/vhosts/www.localize.im/htdocs/classes/UI.php(208): UI::getPage_Project(Array, Array) #4 /srv/data/web/vhosts/www.localize.im/htdocs/classes/UI.php(183): UI::findPage(6, Array, Array) #5 /srv/data/web/vhosts/www.localize.im/htdocs/index.php(226): UI::getPage(6) #6 {main} thrown in /srv/data/web/vhosts/www.localize.im/htdocs/classes/Language.php on line 423

## Discussion & Remediation Timeline
