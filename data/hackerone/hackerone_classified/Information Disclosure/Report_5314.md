# HackerOne Report: Coinbase Android Application - Bitcoin Wallet Leaks OAuth Response Code
**Report ID:** 5314
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
Hi,

There's a simple bug here, the Coinbase Android App. "BitCoin Wallet" leaks the **OAuth** Response Code which can be obtained using `adb logcat -s Coinbase` command line for testing, and any Android application on the same phone can read the response code for the user by reading the logs. As of now nothing can be harmed with OAuth Response code, but along with the hardcoded `client secret` we can obtain the `access_token`.

This bug is similar to this - http://attack-secure.com/all-your-facebook-access-tokens-are-belong-to-us/

So using the stolen response code and `client secret` we can derive the `access_token`

POC: https://www.dropbox.com/s/zionksi1pt7lot5/Coinbase-Android.mov

## Discussion & Remediation Timeline
