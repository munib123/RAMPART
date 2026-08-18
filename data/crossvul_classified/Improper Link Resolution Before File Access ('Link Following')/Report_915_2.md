# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in c
**Pair ID:** 915_2
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `915_2`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```c
Lines 81-121 of the vulnerable file.

    static bool saveToFile(const QString &fileName, const QByteArray &data, bool override = true);
    static bool isBlockSpecialFile(const QString &fileName);
    static bool isPartcloneFile(const QString &fileName);
    static bool isDiskDevice(const QString &devicePath);
    static bool isPartitionDevice(const QString &devicePath);
    static QString parentDevice(const QString &device);
    static bool deviceHaveKinship(const QString &device1, const QString &device2);

    static int clonePartition(const DPartInfo &part, const QString &to, bool override = true);
    static int restorePartition(const QString &from, const DPartInfo &to);

    static bool existLiveSystem();
    static bool restartToLiveSystem(const QStringList &arguments);

    static bool isDeepinSystem(const DPartInfo &part);
    static bool resetPartUUID(const DPartInfo &part, QByteArray uuid = QByteArray());

    static QString getDeviceForFile(const QString &file, QString *rootPath = 0);
    static QString parseSerialUrl(const QString &urlString, QString *errorString = 0);
    static QString toSerialUrl(const QString &file);

signals:
    void newWarning(const QString &message);
    void newError(const QString &message);

private:
    static QByteArray m_processStandardOutput;
    static QByteArray m_processStandardError;

    QString m_warningString;
    QString m_errorString;
};

template<typename... Args>
static
typename QtPrivate::QEnableIf<int(sizeof...(Args)) >= 1, QString>::Type
__d_asprintf__(const char *format, Args&&... args)
{
    return QString::asprintf(format, std::forward<Args>(args)...);
}
template<typename... Args>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -99,6 +99,8 @@
     static QString parseSerialUrl(const QString &urlString, QString *errorString = 0);
     static QString toSerialUrl(const QString &file);
 
+    static bool clearSymlink(const QString &path);
+
 signals:
     void newWarning(const QString &message);
     void newError(const QString &message);
```
