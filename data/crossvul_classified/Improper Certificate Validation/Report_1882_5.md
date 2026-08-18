# CrossVul Fix Pair: Improper Certificate Validation in shell
**Pair ID:** 1882_5
**Vulnerability Class:** Improper Certificate Validation
**CWE:** CWE-295
**Language:** shell
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1882_5`)

## Vulnerability Information & PoC

## Description
Improper Certificate Validation - When a certificate is invalid or malicious, it might allow an attacker to spoof a trusted entity by interfering in the communication path between the host and client.

## Vulnerable Code
```bash
Lines 1-23 of the vulnerable file.

#!/bin/sh
set -ev
VERSION=5.56
DST=stunnel-$VERSION-android

# install Android NDK on Arch Linux:
# aurman -S android-ndk-14b

# install Android NDK on Debian:
# sudo apt install google-android-ndk-installer

# build OpenSSL:
# export ANDROID_NDK=/usr/lib/android-ndk
# export PATH=$ANDROID_NDK/toolchains/arm-linux-androideabi-4.9/prebuilt/linux-x86_64/bin:$PATH
# ./Configure no-shared --prefix=/opt/openssl-android --openssldir=/data/local/tmp/ssl android-arm -D__ANDROID_API__=14
# make
# sudo PATH=$ANDROID_NDK/toolchains/arm-linux-androideabi-4.9/prebuilt/linux-x86_64/bin:$PATH make install

# Debian does not deploy /etc/profile.d/android-ndk.sh
test -d "$ANDROID_NDK" || ANDROID_NDK=/usr/lib/android-ndk

ANDROID_SYSROOT=$ANDROID_NDK/platforms/android-14/arch-arm
export CPPFLAGS="--sysroot=$ANDROID_SYSROOT"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,6 @@
 #!/bin/sh
 set -ev
-VERSION=5.56
+VERSION=5.57
 DST=stunnel-$VERSION-android
 
 # install Android NDK on Arch Linux:
```
