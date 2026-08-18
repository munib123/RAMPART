# CrossVul Fix Pair: Unquoted Search Path or Element in cpp
**Pair ID:** 4196_0
**Vulnerability Class:** Unquoted Search Path or Element
**CWE:** CWE-428
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4196_0`)

## Vulnerability Information & PoC

## Description
Unquoted Search Path or Element - If a malicious individual has access to the file system, it is possible to elevate privileges by inserting such a file as C:Program.

## Vulnerable Code
```cpp
Lines 141-181 of the vulnerable file.

			else
			{
				break;
			}
		}

		if( status.dwCurrentState != SERVICE_STOPPED )
		{
			vWarning() << "service" << m_name << "could not be stopped.";
			return false;
		}
	}

	return true;
}



bool WindowsServiceControl::install( const QString& filePath, const QString& displayName  )
{
	m_serviceHandle = CreateService(
				m_serviceManager,		// SCManager database
				WindowsCoreFunctions::toConstWCharArray( m_name ),	// name of service
				WindowsCoreFunctions::toConstWCharArray( displayName ),// name to display
				SERVICE_ALL_ACCESS,	// desired access
				SERVICE_WIN32_OWN_PROCESS,
				// service type
				SERVICE_AUTO_START,	// start type
				SERVICE_ERROR_NORMAL,	// error control type
				WindowsCoreFunctions::toConstWCharArray( filePath ),		// service's binary
				nullptr,			// no load ordering group
				nullptr,			// no tag identifier
				L"Tcpip\0RpcSs\0\0",		// dependencies
				nullptr,			// LocalSystem account
				nullptr );			// no password

	if( m_serviceHandle == nullptr )
	{
		const auto error = GetLastError();
		if( error == ERROR_SERVICE_EXISTS )
		{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -158,6 +158,8 @@
 
 bool WindowsServiceControl::install( const QString& filePath, const QString& displayName  )
 {
+	const auto binaryPath = QStringLiteral("\"%1\"").arg( QString( filePath ).replace( QLatin1Char('"'), QString() ) );
+
 	m_serviceHandle = CreateService(
 				m_serviceManager,		// SCManager database
 				WindowsCoreFunctions::toConstWCharArray( m_name ),	// name of service
@@ -167,7 +169,7 @@
 				// service type
 				SERVICE_AUTO_START,	// start type
 				SERVICE_ERROR_NORMAL,	// error control type
-				WindowsCoreFunctions::toConstWCharArray( filePath ),		// service's binary
+				WindowsCoreFunctions::toConstWCharArray( binaryPath ),		// service's binary
 				nullptr,			// no load ordering group
 				nullptr,			// no tag identifier
 				L"Tcpip\0RpcSs\0\0",		// dependencies
```
