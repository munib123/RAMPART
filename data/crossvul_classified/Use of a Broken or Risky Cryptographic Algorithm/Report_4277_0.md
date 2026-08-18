# CrossVul Fix Pair: Use of a Broken or Risky Cryptographic Algorithm in cpp
**Pair ID:** 4277_0
**Vulnerability Class:** Use of a Broken or Risky Cryptographic Algorithm
**CWE:** CWE-327
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4277_0`)

## Vulnerability Information & PoC

## Description
Use of a Broken or Risky Cryptographic Algorithm - Cryptographic algorithms are the methods by which data is scrambled to prevent observation or influence by unauthorized actors.

## Vulnerable Code
```cpp
Lines 3223-3267 of the vulnerable file.

        int delta = m_player->position() - MLT.producer()->get_out();
        emit m_player->outChanged(delta);
    }
}

void MainWindow::onShuttle(float x)
{
    if (x == 0) {
        m_player->pause();
    } else if (x > 0) {
        m_player->play(10.0 * x);
    } else {
        m_player->play(20.0 * x);
    }
}

void MainWindow::showUpgradePrompt()
{
    if (Settings.checkUpgradeAutomatic()) {
        showStatusMessage("Checking for upgrade...");
        QNetworkRequest request(QUrl("https://check.shotcut.org/version.json"));
        QSslConfiguration sslConfig = request.sslConfiguration();
        sslConfig.setPeerVerifyMode(QSslSocket::VerifyNone);
        request.setSslConfiguration(sslConfig);
        m_network.get(request);
    } else {
        m_network.setStrictTransportSecurityEnabled(false);
        QAction* action = new QAction(tr("Click here to check for a new version of Shotcut."), 0);
        connect(action, SIGNAL(triggered(bool)), SLOT(on_actionUpgrade_triggered()));
        showStatusMessage(action, 15 /* seconds */);
    }
}

void MainWindow::on_actionRealtime_triggered(bool checked)
{
    Settings.setPlayerRealtime(checked);
    if (Settings.playerGPU())
        MLT.pause();
    if (MLT.consumer()) {
        MLT.restart();
    }

}

void MainWindow::on_actionProgressive_triggered(bool checked)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3240,13 +3240,8 @@
 {
     if (Settings.checkUpgradeAutomatic()) {
         showStatusMessage("Checking for upgrade...");
-        QNetworkRequest request(QUrl("https://check.shotcut.org/version.json"));
-        QSslConfiguration sslConfig = request.sslConfiguration();
-        sslConfig.setPeerVerifyMode(QSslSocket::VerifyNone);
-        request.setSslConfiguration(sslConfig);
-        m_network.get(request);
+        m_network.get(QNetworkRequest(QUrl("https://check.shotcut.org/version.json")));
     } else {
-        m_network.setStrictTransportSecurityEnabled(false);
         QAction* action = new QAction(tr("Click here to check for a new version of Shotcut."), 0);
         connect(action, SIGNAL(triggered(bool)), SLOT(on_actionUpgrade_triggered()));
         showStatusMessage(action, 15 /* seconds */);
@@ -3702,7 +3697,7 @@
             Settings.setAskUpgradeAutomatic(false);
     }
     showStatusMessage("Checking for upgrade...");
-    m_network.get(QNetworkRequest(QUrl("http://check.shotcut.org/version.json")));
+    m_network.get(QNetworkRequest(QUrl("https://check.shotcut.org/version.json")));
 }
 
 void MainWindow::on_actionOpenXML_triggered()
```
