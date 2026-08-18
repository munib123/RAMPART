# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in cpp
**Pair ID:** 3200_4
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3200_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```cpp
Lines 384-424 of the vulnerable file.

    // Adding Peer to peer list
    m_listModel->insertRow(row);
    m_listModel->setData(m_listModel->index(row, PeerListDelegate::IP), ip);
    m_listModel->setData(m_listModel->index(row, PeerListDelegate::IP), ip, Qt::ToolTipRole);
    m_listModel->setData(m_listModel->index(row, PeerListDelegate::PORT), peer.address().port);
    m_listModel->setData(m_listModel->index(row, PeerListDelegate::IP_HIDDEN), ip);
    if (m_resolveCountries) {
        const QIcon ico = GuiIconProvider::instance()->getFlagIcon(peer.country());
        if (!ico.isNull()) {
            m_listModel->setData(m_listModel->index(row, PeerListDelegate::COUNTRY), ico, Qt::DecorationRole);
            const QString countryName = Net::GeoIPManager::CountryName(peer.country());
            m_listModel->setData(m_listModel->index(row, PeerListDelegate::COUNTRY), countryName, Qt::ToolTipRole);
        }
        else {
            m_missingFlags.insert(ip);
        }
    }
    m_listModel->setData(m_listModel->index(row, PeerListDelegate::CONNECTION), peer.connectionType());
    m_listModel->setData(m_listModel->index(row, PeerListDelegate::FLAGS), peer.flags());
    m_listModel->setData(m_listModel->index(row, PeerListDelegate::FLAGS), peer.flagsDescription(), Qt::ToolTipRole);
    m_listModel->setData(m_listModel->index(row, PeerListDelegate::CLIENT), peer.client());
    m_listModel->setData(m_listModel->index(row, PeerListDelegate::PROGRESS), peer.progress());
    m_listModel->setData(m_listModel->index(row, PeerListDelegate::DOWN_SPEED), peer.payloadDownSpeed());
    m_listModel->setData(m_listModel->index(row, PeerListDelegate::UP_SPEED), peer.payloadUpSpeed());
    m_listModel->setData(m_listModel->index(row, PeerListDelegate::TOT_DOWN), peer.totalDownload());
    m_listModel->setData(m_listModel->index(row, PeerListDelegate::TOT_UP), peer.totalUpload());
    m_listModel->setData(m_listModel->index(row, PeerListDelegate::RELEVANCE), peer.relevance());
    QStringList downloadingFiles(torrent->info().filesForPiece(peer.downloadingPieceIndex()));
    m_listModel->setData(m_listModel->index(row, PeerListDelegate::DOWNLOADING_PIECE), downloadingFiles.join(QLatin1String(";")));
    m_listModel->setData(m_listModel->index(row, PeerListDelegate::DOWNLOADING_PIECE), downloadingFiles.join(QLatin1String("\n")), Qt::ToolTipRole);

    return m_listModel->item(row, PeerListDelegate::IP);
}

void PeerListWidget::updatePeer(const QString &ip, BitTorrent::TorrentHandle *const torrent, const BitTorrent::PeerInfo &peer)
{
    QStandardItem *item = m_peerItems.value(ip);
    int row = item->row();
    if (m_resolveCountries) {
        const QIcon ico = GuiIconProvider::instance()->getFlagIcon(peer.country());
        if (!ico.isNull()) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -401,7 +401,7 @@
     m_listModel->setData(m_listModel->index(row, PeerListDelegate::CONNECTION), peer.connectionType());
     m_listModel->setData(m_listModel->index(row, PeerListDelegate::FLAGS), peer.flags());
     m_listModel->setData(m_listModel->index(row, PeerListDelegate::FLAGS), peer.flagsDescription(), Qt::ToolTipRole);
-    m_listModel->setData(m_listModel->index(row, PeerListDelegate::CLIENT), peer.client());
+    m_listModel->setData(m_listModel->index(row, PeerListDelegate::CLIENT), Utils::String::toHtmlEscaped(peer.client()));
     m_listModel->setData(m_listModel->index(row, PeerListDelegate::PROGRESS), peer.progress());
     m_listModel->setData(m_listModel->index(row, PeerListDelegate::DOWN_SPEED), peer.payloadDownSpeed());
     m_listModel->setData(m_listModel->index(row, PeerListDelegate::UP_SPEED), peer.payloadUpSpeed());
@@ -432,7 +432,7 @@
     m_listModel->setData(m_listModel->index(row, PeerListDelegate::PORT), peer.address().port);
     m_listModel->setData(m_listModel->index(row, PeerListDelegate::FLAGS), peer.flags());
     m_listModel->setData(m_listModel->index(row, PeerListDelegate::FLAGS), peer.flagsDescription(), Qt::ToolTipRole);
-    m_listModel->setData(m_listModel->index(row, PeerListDelegate::CLIENT), peer.client());
+    m_listModel->setData(m_listModel->index(row, PeerListDelegate::CLIENT), Utils::String::toHtmlEscaped(peer.client()));
     m_listModel->setData(m_listModel->index(row, PeerListDelegate::PROGRESS), peer.progress());
     m_listModel->setData(m_listModel->index(row, PeerListDelegate::DOWN_SPEED), peer.payloadDownSpeed());
     m_listModel->setData(m_listModel->index(row, PeerListDelegate::UP_SPEED), peer.payloadUpSpeed());
```
