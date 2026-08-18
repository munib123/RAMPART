# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in cpp
**Pair ID:** 915_4
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `915_4`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```cpp
Lines 85-125 of the vulnerable file.


    return false;
}

static QString logFormat = "[%{time}{yyyy-MM-dd, HH:mm:ss.zzz}] [%{type:-7}] [%{file}=>%{function}: %{line}] %{message}\n";

int main(int argc, char *argv[])
{
    QCoreApplication *a;

    if (isTUIMode(argc, argv)) {
        Global::isTUIMode = true;

        a = new QCoreApplication(argc, argv);
    }
#ifdef ENABLE_GUI
    else {
        ConsoleAppender *consoleAppender = new ConsoleAppender;
        consoleAppender->setFormat(logFormat);

        RollingFileAppender *rollingFileAppender = new RollingFileAppender("/tmp/.deepin-clone.log");
        rollingFileAppender->setFormat(logFormat);
        rollingFileAppender->setLogFilesLimit(5);
        rollingFileAppender->setDatePattern(RollingFileAppender::DailyRollover);

        logger->registerAppender(consoleAppender);
        logger->registerAppender(rollingFileAppender);

        if (qEnvironmentVariableIsSet("PKEXEC_UID")) {
            const quint32 pkexec_uid = qgetenv("PKEXEC_UID").toUInt();
            const QDir user_home(getpwuid(pkexec_uid)->pw_dir);

            QFile pam_file(user_home.absoluteFilePath(".pam_environment"));

            if (pam_file.open(QIODevice::ReadOnly)) {
                while (!pam_file.atEnd()) {
                    const QByteArray &line = pam_file.readLine().simplified();

                    if (line.startsWith("QT_SCALE_FACTOR")) {
                        const QByteArrayList &list = line.split('=');

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -102,36 +102,20 @@
         ConsoleAppender *consoleAppender = new ConsoleAppender;
         consoleAppender->setFormat(logFormat);
 
-        RollingFileAppender *rollingFileAppender = new RollingFileAppender("/tmp/.deepin-clone.log");
+        const QString log_file("/var/log/deepin-clone.log");
+
+        RollingFileAppender *rollingFileAppender = new RollingFileAppender(log_file);
         rollingFileAppender->setFormat(logFormat);
         rollingFileAppender->setLogFilesLimit(5);
         rollingFileAppender->setDatePattern(RollingFileAppender::DailyRollover);
 
+        logger->registerAppender(rollingFileAppender);
         logger->registerAppender(consoleAppender);
-        logger->registerAppender(rollingFileAppender);
 
         if (qEnvironmentVariableIsSet("PKEXEC_UID")) {
             const quint32 pkexec_uid = qgetenv("PKEXEC_UID").toUInt();
-            const QDir user_home(getpwuid(pkexec_uid)->pw_dir);
-
-            QFile pam_file(user_home.absoluteFilePath(".pam_environment"));
-
-            if (pam_file.open(QIODevice::ReadOnly)) {
-                while (!pam_file.atEnd()) {
-                    const QByteArray &line = pam_file.readLine().simplified();
-
-                    if (line.startsWith("QT_SCALE_FACTOR")) {
-                        const QByteArrayList &list = line.split('=');
-
-                        if (list.count() == 2) {
-                            qputenv("QT_SCALE_FACTOR", list.last());
-                            break;
-                        }
-                    }
-                }
-
-                pam_file.close();
-            }
+
+            DApplication::customQtThemeConfigPathByUserHome(getpwuid(pkexec_uid)->pw_dir);
         }
 
         DApplication::loadDXcbPlugin();
```
