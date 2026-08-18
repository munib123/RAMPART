# CrossVul Fix Pair: Improper Input Validation in cpp
**Pair ID:** 2181_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2181_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```cpp
Lines 286-327 of the vulnerable file.

    Status CmdAuthenticate::_authenticateX509(const UserName& user, const BSONObj& cmdObj) {
        if (!getSSLManager()) {
            return Status(ErrorCodes::ProtocolError,
                          "SSL support is required for the MONGODB-X509 mechanism.");
        }
        if(user.getDB() != "$external") {
            return Status(ErrorCodes::ProtocolError,
                          "X.509 authentication must always use the $external database.");
        }

        ClientBasic *client = ClientBasic::getCurrent();
        AuthorizationSession* authorizationSession = client->getAuthorizationSession();
        std::string subjectName = client->port()->getX509SubjectName();

        if (user.getUser() != subjectName) {
            return Status(ErrorCodes::AuthenticationFailed,
                          "There is no x.509 client certificate matching the user.");
        }
        else {
            std::string srvSubjectName = getSSLManager()->getServerSubjectName();
            std::string srvClusterId = srvSubjectName.substr(srvSubjectName.find(",OU="));
            std::string peerClusterId = subjectName.substr(subjectName.find(",OU="));

            fassert(17002, !srvClusterId.empty() && srvClusterId != srvSubjectName);

            // Handle internal cluster member auth, only applies to server-server connections
            int clusterAuthMode = serverGlobalParams.clusterAuthMode.load(); 
            if (srvClusterId == peerClusterId) {
                if (clusterAuthMode == ServerGlobalParams::ClusterAuthMode_undefined ||
                    clusterAuthMode == ServerGlobalParams::ClusterAuthMode_keyFile) {
                    return Status(ErrorCodes::AuthenticationFailed, "The provided certificate " 
                                  "can only be used for cluster authentication, not client " 
                                  "authentication. The current configuration does not allow " 
                                  "x.509 cluster authentication, check the --clusterAuthMode flag");
                }
                authorizationSession->grantInternalAuthorization();
            }
            // Handle normal client authentication, only applies to client-server connections
            else {
                if (_isX509AuthDisabled) {
                    return Status(ErrorCodes::BadValue,
                                  _x509AuthenticationDisabledMessage);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -303,14 +303,18 @@
         }
         else {
             std::string srvSubjectName = getSSLManager()->getServerSubjectName();
-            std::string srvClusterId = srvSubjectName.substr(srvSubjectName.find(",OU="));
-            std::string peerClusterId = subjectName.substr(subjectName.find(",OU="));
-
-            fassert(17002, !srvClusterId.empty() && srvClusterId != srvSubjectName);
+            
+            size_t srvClusterIdPos = srvSubjectName.find(",OU=");
+            size_t peerClusterIdPos = subjectName.find(",OU=");
+
+            std::string srvClusterId = srvClusterIdPos != std::string::npos ? 
+                srvSubjectName.substr(srvClusterIdPos) : "";
+            std::string peerClusterId = peerClusterIdPos != std::string::npos ? 
+                subjectName.substr(peerClusterIdPos) : "";
 
             // Handle internal cluster member auth, only applies to server-server connections
             int clusterAuthMode = serverGlobalParams.clusterAuthMode.load(); 
-            if (srvClusterId == peerClusterId) {
+            if (srvClusterId == peerClusterId && !srvClusterId.empty()) {
                 if (clusterAuthMode == ServerGlobalParams::ClusterAuthMode_undefined ||
                     clusterAuthMode == ServerGlobalParams::ClusterAuthMode_keyFile) {
                     return Status(ErrorCodes::AuthenticationFailed, "The provided certificate " 
```
