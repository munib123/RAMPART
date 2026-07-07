# HackerOne Report: Bug in iOS application which could lead to unauthorised access.
**Report ID:** 7036
**Vulnerability Class:** Improper Authentication - Generic

## Vulnerability Information & PoC
Hi,

The file under the Preferences folder within the iOS application stores sensitive information: com.irccloud.IRCCloud.plist. This file stores the user's authenticated session identifier. Stealing this information would allow unauthorised access to a user's account.

The content of the file can be seen in the file attached to this report.

This file is accessible from the phone even while the phone is locked with a passcode suggesting that the application does not secure the file using the appropriate data protection class.

This can also be verified by using the tool available at the following link:

https://github.com/ciso/ios-dataprotection/

If a user is logged into the application, all that an attacker needs to do is surreptitiously take the phone and dump the file within the folder. This would work while the phone is locked and does not require the phone to be jailbroken.

I should also mention that I haven't looked through all the files, but any sensitive file with the Protection class set to anything other than NSFileProtectionComplete would be extractable from the iPhone without requiring the passcode.

If you would like to test this, you can use the ios-data protection tool mentioned above or extract the data with iExplorer (Demo version) while the phone is locked and the user logged in.

More information regarding data protection is available here:

https://developer.apple.com/library/ios/documentation/iPhone/Conceptual/iPhoneOSProgrammingGuide/AdvancedAppTricks/AdvancedAppTricks.html#//apple_ref/doc/uid/TP40007072-CH7-SW24

## Discussion & Remediation Timeline
