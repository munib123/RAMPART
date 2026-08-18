# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in c
**Pair ID:** 3200_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3200_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```c
Lines 18-58 of the vulnerable file.

 *
 * In addition, as a special exception, the copyright holders give permission to
 * link this program with the OpenSSL project's "OpenSSL" library (or with
 * modified versions of it that use the same license as the "OpenSSL" library),
 * and distribute the linked executables. You must obey the GNU General Public
 * License in all respects for all of the code used other than "OpenSSL".  If you
 * modify file(s), you may extend this exception to your version of the file(s),
 * but you are not obligated to do so. If you do not wish to do so, delete this
 * exception statement from your version.
 *
 * Contact : chris@qbittorrent.org
 */

#ifndef DELETIONCONFIRMATIONDLG_H
#define DELETIONCONFIRMATIONDLG_H

#include <QDialog>
#include <QPushButton>
#include "ui_confirmdeletiondlg.h"
#include "base/preferences.h"
#include "guiiconprovider.h"
#include "base/utils/misc.h"

class DeletionConfirmationDlg : public QDialog, private Ui::confirmDeletionDlg {
  Q_OBJECT

  public:
  DeletionConfirmationDlg(QWidget *parent, const int &size, const QString &name, bool defaultDeleteFiles): QDialog(parent) {
    setupUi(this);
    if (size == 1)
      label->setText(tr("Are you sure you want to delete '%1' from the transfer list?", "Are you sure you want to delete 'ubuntu-linux-iso' from the transfer list?").arg(name));
    else
      label->setText(tr("Are you sure you want to delete these %1 torrents from the transfer list?", "Are you sure you want to delete these 5 torrents from the transfer list?").arg(QString::number(size)));
    // Icons
    lbl_warn->setPixmap(GuiIconProvider::instance()->getIcon("dialog-warning").pixmap(lbl_warn->height()));
    lbl_warn->setFixedWidth(lbl_warn->height());
    rememberBtn->setIcon(GuiIconProvider::instance()->getIcon("object-locked"));

    move(Utils::Misc::screenCenter(this));
    checkPermDelete->setChecked(defaultDeleteFiles || Preferences::instance()->deleteTorrentFilesAsDefault());
    connect(checkPermDelete, SIGNAL(clicked()), this, SLOT(updateRememberButtonState()));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -35,8 +35,9 @@
 #include <QPushButton>
 #include "ui_confirmdeletiondlg.h"
 #include "base/preferences.h"
+#include "base/utils/misc.h"
+#include "base/utils/string.h"
 #include "guiiconprovider.h"
-#include "base/utils/misc.h"
 
 class DeletionConfirmationDlg : public QDialog, private Ui::confirmDeletionDlg {
   Q_OBJECT
@@ -45,7 +46,7 @@
   DeletionConfirmationDlg(QWidget *parent, const int &size, const QString &name, bool defaultDeleteFiles): QDialog(parent) {
     setupUi(this);
     if (size == 1)
-      label->setText(tr("Are you sure you want to delete '%1' from the transfer list?", "Are you sure you want to delete 'ubuntu-linux-iso' from the transfer list?").arg(name));
+      label->setText(tr("Are you sure you want to delete '%1' from the transfer list?", "Are you sure you want to delete 'ubuntu-linux-iso' from the transfer list?").arg(Utils::String::toHtmlEscaped(name)));
     else
       label->setText(tr("Are you sure you want to delete these %1 torrents from the transfer list?", "Are you sure you want to delete these 5 torrents from the transfer list?").arg(QString::number(size)));
     // Icons
```
