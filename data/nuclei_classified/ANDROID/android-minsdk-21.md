# Vulnerability: AndroidManifest.xml minSdkVersion Set to 21 (Insecure Minimum SDK Version)
**Classification:** ANDROID
**Source:** Nuclei Template (`android-minsdk-21.yaml`)

## Description
The AndroidManifest.xml file specifies the minSdkVersion as 21, which permits the application to run on devices with outdated Android versions. Older Android platforms may lack essential security features and are more likely to contain known vulnerabilities, increasing the overall risk to the application and its users.

