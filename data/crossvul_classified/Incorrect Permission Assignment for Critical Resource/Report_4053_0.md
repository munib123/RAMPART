# CrossVul Fix Pair: Incorrect Default Permissions in cpp
**Pair ID:** 4053_0
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-276
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4053_0`)

## Vulnerability Information & PoC

## Description
Incorrect Default Permissions - During installation, installed file permissions are set to allow anyone to modify those files.

## Vulnerable Code
```cpp
Lines 427-468 of the vulnerable file.

                        fileTemplate.end());
    int fd = mkstemp((char*)tempFileName.data());
    if (fd == -1)
    {
        log<level::DEBUG>("Error creating temp file");
        return -EIO;
    }

    std::string strTempFileName(tempFileName.data());
    // Open the temp file for writing from provided fd
    // By "true", remove it at exit if still there.
    // This is needed to cleanup the temp file at exception
    phosphor::user::File temp(fd, strTempFileName, "w", true);
    if ((temp)() == NULL)
    {
        close(fd);
        log<level::DEBUG>("Error creating temp file");
        return -EIO;
    }

    // Set the file mode as of actual ipmi-pass file.
    if (fchmod(fileno((temp)()), st.st_mode) < 0)
    {
        log<level::DEBUG>("Error setting fchmod for temp file");
        return -EIO;
    }

    const EVP_MD* digest = EVP_sha256();
    size_t hashLen = EVP_MD_block_size(digest);
    std::vector<uint8_t> hash(hashLen);
    size_t ivLen = EVP_CIPHER_iv_length(cipher);
    std::vector<uint8_t> iv(ivLen);
    std::array<uint8_t, EVP_MAX_KEY_LENGTH> key;
    size_t keyLen = key.size();
    std::array<uint8_t, EVP_MAX_MD_SIZE> mac;
    size_t macLen = mac.size();

    // Create random hash and generate hash key which will be used for
    // encryption.
    if (RAND_bytes(hash.data(), hashLen) != 1)
    {
        log<level::DEBUG>("Hash genertion failed, bailing out");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -444,8 +444,8 @@
         return -EIO;
     }
 
-    // Set the file mode as of actual ipmi-pass file.
-    if (fchmod(fileno((temp)()), st.st_mode) < 0)
+    // Set the file mode as read-write for owner only
+    if (fchmod(fileno((temp)()), S_IRUSR | S_IWUSR) < 0)
     {
         log<level::DEBUG>("Error setting fchmod for temp file");
         return -EIO;
```
