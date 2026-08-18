# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in cpp
**Pair ID:** 3200_5
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3200_5`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```cpp
Lines 297-337 of the vulnerable file.

void PropertiesWidget::loadTorrentInfos(BitTorrent::TorrentHandle *const torrent)
{
    clear();
    m_torrent = torrent;
    downloaded_pieces->setTorrent(m_torrent);
    pieces_availability->setTorrent(m_torrent);
    if (!m_torrent) return;

    // Save path
    updateSavePath(m_torrent);
    // Hash
    hash_lbl->setText(m_torrent->hash());
    PropListModel->model()->clear();
    if (m_torrent->hasMetadata()) {
        // Creation date
        lbl_creationDate->setText(m_torrent->creationDate().toString(Qt::DefaultLocaleShortDate));

        label_total_size_val->setText(Utils::Misc::friendlyUnit(m_torrent->totalSize()));

        // Comment
        comment_text->setText(Utils::Misc::parseHtmlLinks(m_torrent->comment()));

        // URL seeds
        loadUrlSeeds();

        label_created_by_val->setText(m_torrent->creator());

        // List files in torrent
        PropListModel->model()->setupModelData(m_torrent->info());
        filesList->setExpanded(PropListModel->index(0, 0), true);

        // Load file priorities
        PropListModel->model()->updateFilesPriorities(m_torrent->filePriorities());
    }
    // Load dynamic data
    loadDynamicData();
}

void PropertiesWidget::readSettings()
{
    const Preferences *const pref = Preferences::instance();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -314,12 +314,12 @@
         label_total_size_val->setText(Utils::Misc::friendlyUnit(m_torrent->totalSize()));
 
         // Comment
-        comment_text->setText(Utils::Misc::parseHtmlLinks(m_torrent->comment()));
+        comment_text->setText(Utils::Misc::parseHtmlLinks(Utils::String::toHtmlEscaped(m_torrent->comment())));
 
         // URL seeds
         loadUrlSeeds();
 
-        label_created_by_val->setText(m_torrent->creator());
+        label_created_by_val->setText(Utils::String::toHtmlEscaped(m_torrent->creator()));
 
         // List files in torrent
         PropListModel->model()->setupModelData(m_torrent->info());
```
