# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in cpp
**Pair ID:** 1993_0
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1993_0`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```cpp
Lines 1248-1289 of the vulnerable file.

void ConnectDialog::on_qaFavoriteCopy_triggered() {
	ServerItem *si = static_cast<ServerItem *>(qtwServers->currentItem());
	if (! si)
		return;

	QApplication::clipboard()->setMimeData(si->toMimeData());
}

void ConnectDialog::on_qaFavoritePaste_triggered() {
	ServerItem *si = ServerItem::fromMimeData(QApplication::clipboard()->mimeData());
	if (! si)
		return;

	qlItems << si;
	qtwServers->siFavorite->addServerItem(si);
	qtwServers->setCurrentItem(si);
	startDns(si);
}

void ConnectDialog::on_qaUrl_triggered() {
	ServerItem *si = static_cast<ServerItem *>(qtwServers->currentItem());
	if (! si || si->qsUrl.isEmpty())
		return;

	QDesktopServices::openUrl(QUrl(si->qsUrl));
}

void ConnectDialog::onFiltersTriggered(QAction *act) {
	if (act == qaShowAll)
		g.s.ssFilter = Settings::ShowAll;
	else if (act == qaShowReachable)
		g.s.ssFilter = Settings::ShowReachable;
	else if (act == qaShowPopulated)
		g.s.ssFilter = Settings::ShowPopulated;

	foreach(ServerItem *si, qlItems)
		si->hideCheck();
}

void ConnectDialog::on_qtwServers_customContextMenuRequested(const QPoint &mpos) {
	ServerItem *si = static_cast<ServerItem *>(qtwServers->itemAt(mpos));
	qmPopup->clear();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1265,11 +1265,25 @@
 }
 
 void ConnectDialog::on_qaUrl_triggered() {
-	ServerItem *si = static_cast<ServerItem *>(qtwServers->currentItem());
-	if (! si || si->qsUrl.isEmpty())
+	auto *si = static_cast< const ServerItem * >(qtwServers->currentItem());
+	if (!si || si->qsUrl.isEmpty()) {
 		return;
-
-	QDesktopServices::openUrl(QUrl(si->qsUrl));
+	}
+
+	const QStringList allowedSchemes = { QLatin1String("http"), QLatin1String("https") };
+
+	const auto url = QUrl(si->qsUrl);
+	if (allowedSchemes.contains(url.scheme())) {
+		QDesktopServices::openUrl(url);
+	} else {
+		// Inform user that the requested URL has been blocked
+		QMessageBox msgBox;
+		msgBox.setText(QObject::tr("<b>Blocked URL scheme \"%1\"</b>").arg(url.scheme()));
+		msgBox.setInformativeText(QObject::tr("The URL uses a scheme that has been blocked for security reasons."));
+		msgBox.setDetailedText(QObject::tr("Blocked URL: \"%1\"").arg(url.toString()));
+		msgBox.setIcon(QMessageBox::Warning);
+		msgBox.exec();
+	}
 }
 
 void ConnectDialog::onFiltersTriggered(QAction *act) {
```
