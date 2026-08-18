# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in cpp
**Pair ID:** 74_1
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `74_1`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```cpp
Lines 347-388 of the vulnerable file.

    zip.close();
    if(zip.getZipError()!=0) {
        removeFile(extracted);
        return QStringList();
    }

    return extracted;
}

QStringList JlCompress::extractDir(QString fileCompressed, QString dir) {
    // Apro lo zip
    QuaZip zip(fileCompressed);
    return extractDir(zip, dir);
}

QStringList JlCompress::extractDir(QuaZip &zip, const QString &dir)
{
    if(!zip.open(QuaZip::mdUnzip)) {
        return QStringList();
    }

    QDir directory(dir);
    QStringList extracted;
    if (!zip.goToFirstFile()) {
        return QStringList();
    }
    do {
        QString name = zip.getCurrentFileName();
        QString absFilePath = directory.absoluteFilePath(name);
        if (!extractFile(&zip, "", absFilePath)) {
            removeFile(extracted);
            return QStringList();
        }
        extracted.append(absFilePath);
    } while (zip.goToNextFile());

    // Chiudo il file zip
    zip.close();
    if(zip.getZipError()!=0) {
        removeFile(extracted);
        return QStringList();
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -364,8 +364,9 @@
     if(!zip.open(QuaZip::mdUnzip)) {
         return QStringList();
     }
-
-    QDir directory(dir);
+    QString cleanDir = QDir::cleanPath(dir);
+    QDir directory(cleanDir);
+    QString absCleanDir = directory.absolutePath();
     QStringList extracted;
     if (!zip.goToFirstFile()) {
         return QStringList();
@@ -373,6 +374,9 @@
     do {
         QString name = zip.getCurrentFileName();
         QString absFilePath = directory.absoluteFilePath(name);
+        QString absCleanPath = QDir::cleanPath(absFilePath);
+        if (!absCleanPath.startsWith(absCleanDir + "/"))
+            continue;
         if (!extractFile(&zip, "", absFilePath)) {
             removeFile(extracted);
             return QStringList();
```
