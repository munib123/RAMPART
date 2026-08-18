# CrossVul Fix Pair: Improper Authentication in php
**Pair ID:** 5446_0
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5446_0`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```php
Lines 15-60 of the vulnerable file.

 * @license  http://www.gnu.org/licenses/agpl AGPL
 * @link     http://github.com/owncloud/apps
 */
class OC_User_SMB extends \OCA\user_external\Base{
	private $host;

	const SMBCLIENT = 'smbclient -L';
	const LOGINERROR = 'NT_STATUS_LOGON_FAILURE';

	/**
	 * Create new samba authentication provider
	 *
	 * @param string $host Hostname or IP of windows machine
	 */
	public function __construct($host) {
		parent::__construct($host);
		$this->host=$host;
	}

	/**
	 * Check if the password is correct without logging in the user
	 *
	 * @param string $uid      The username
	 * @param string $password The password
	 *
	 * @return true/false
	 */
	public function checkPassword($uid, $password) {
		$uidEscaped=escapeshellarg($uid);
		$password=escapeshellarg($password);
		$result=array();
		$command=self::SMBCLIENT.' //'.$this->host.'/dummy -U'.$uidEscaped.'%'.$password;
		$lastline = exec($command, $output, $retval);
		if ($retval === 127) {
			OCP\Util::writeLog(
				'user_external', 'ERROR: smbclient executable missing',
				OCP\Util::ERROR
			);
			return false;
		} else if (strpos($lastline, self::LOGINERROR) !== false) {
			//normal login error
			return false;
		} else if (strpos($lastline, 'NT_STATUS_BAD_NETWORK_NAME') !== false) {
			//login on minor error
			goto login;
		} else if ($retval != 0) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,18 +32,14 @@
 	}
 
 	/**
-	 * Check if the password is correct without logging in the user
-	 *
-	 * @param string $uid      The username
-	 * @param string $password The password
-	 *
-	 * @return true/false
+	 * @param string $uid
+	 * @param string $password
+	 * @return bool
 	 */
-	public function checkPassword($uid, $password) {
-		$uidEscaped=escapeshellarg($uid);
-		$password=escapeshellarg($password);
-		$result=array();
-		$command=self::SMBCLIENT.' //'.$this->host.'/dummy -U'.$uidEscaped.'%'.$password;
+	private function tryAuthentication($uid, $password) {
+		$uidEscaped = escapeshellarg($uid);
+		$password = escapeshellarg($password);
+		$command = self::SMBCLIENT.' '.escapeshellarg('//' . $this->host . '/dummy').' -U'.$uidEscaped.'%'.$password;
 		$lastline = exec($command, $output, $retval);
 		if ($retval === 127) {
 			OCP\Util::writeLog(
@@ -66,8 +62,33 @@
 			return false;
 		} else {
 			login:
+			return $uid;
+		}
+	}
+
+	/**
+	 * Check if the password is correct without logging in the user
+	 *
+	 * @param string $uid      The username
+	 * @param string $password The password
+	 *
+	 * @return true/false
+	 */
+	public function checkPassword($uid, $password) {
+		// Check with an invalid password, if the user authenticates then fail
+		$attemptWithInvalidPassword = $this->tryAuthentication($uid, base64_encode($password));
+		if(is_string($attemptWithInvalidPassword)) {
+			return false;
+		}
+
+		// Check with valid password
+		$attemptWithValidPassword = $this->tryAuthentication($uid, $password);
+		if(is_string($attemptWithValidPassword)) {
 			$this->storeUser($uid);
 			return $uid;
 		}
+
+		return false;
 	}
 }
+
```
