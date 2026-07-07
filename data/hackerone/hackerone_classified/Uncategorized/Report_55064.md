# HackerOne Report: Bypass Setup by External Activity Invoke
**Report ID:** 55064
**Vulnerability Class:** Uncategorized

## Vulnerability Information & PoC
Tool Used: Drozer
Operating System: Android Kitkat 4.4.2

Note: Make sure the application is running on the device connected to the system.

1. With the help of Drozer tool, list down the activities exported by the application using the following command:
    run app.activity.info -a im.delight.faceless

2.  Once, we have the list try to invoke the activity " im.delight.faceless.ActivityAdd" with the following command:
     run app.activity.start --component im.delight.faceless  im.delight.faceless.ActivityAdd
which will land to "Write Message" screen directly without entering any information in the setup (such as contact number). Now try to publish some text on the given screen and hit "Publish"

3. Now, the application will automatically redirect to a setup screen, after the completion of the setup, it can be viewed that the text that was being published without any authentication is being published with the registered number/user.

## Discussion & Remediation Timeline
