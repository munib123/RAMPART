# CrossVul Fix Pair: Improper Input Validation in java
**Pair ID:** 418_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `418_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```java
Lines 10-50 of the vulnerable file.

import android.net.Uri;
import android.os.Build;
import android.preference.PreferenceManager;
import android.provider.MediaStore;
import android.support.annotation.IdRes;
import android.support.annotation.NonNull;
import android.support.annotation.StringRes;
import android.support.v7.app.AlertDialog;
import android.app.Fragment;
import android.app.PendingIntent;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.IntentSender.SendIntentException;
import android.os.Bundle;
import android.os.Handler;
import android.os.SystemClock;
import android.support.v13.view.inputmethod.InputConnectionCompat;
import android.support.v13.view.inputmethod.InputContentInfoCompat;
import android.text.Editable;
import android.util.Log;
import android.view.ContextMenu;
import android.view.ContextMenu.ContextMenuInfo;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.MotionEvent;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputMethodManager;
import android.widget.AbsListView;
import android.widget.AbsListView.OnScrollListener;
import android.widget.AdapterView;
import android.widget.AdapterView.AdapterContextMenuInfo;
import android.widget.CheckBox;
import android.widget.ListView;
import android.widget.PopupMenu;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -27,6 +27,7 @@
 import android.support.v13.view.inputmethod.InputConnectionCompat;
 import android.support.v13.view.inputmethod.InputContentInfoCompat;
 import android.text.Editable;
+import android.text.TextUtils;
 import android.util.Log;
 import android.view.ContextMenu;
 import android.view.ContextMenu.ContextMenuInfo;
@@ -1995,6 +1996,7 @@
         final String nick = extras.getString(ConversationsActivity.EXTRA_NICK);
         final boolean asQuote = extras.getBoolean(ConversationsActivity.EXTRA_AS_QUOTE);
         final boolean pm = extras.getBoolean(ConversationsActivity.EXTRA_IS_PRIVATE_MESSAGE, false);
+        final boolean doNotAppend = extras.getBoolean(ConversationsActivity.EXTRA_DO_NOT_APPEND, false);
         final List<Uri> uris = extractUris(extras);
         if (uris != null && uris.size() > 0) {
             final List<Uri> cleanedUris = cleanUris(new ArrayList<>(uris));
@@ -2021,7 +2023,7 @@
             if (text != null && asQuote) {
                 quoteText(text);
             } else {
-                appendText(text);
+                appendText(text, doNotAppend);
             }
         }
         final Message message = downloadUuid == null ? null : conversation.findMessageWithFileAndUuid(downloadUuid);
@@ -2545,11 +2547,16 @@
         builder.create().show();
     }
 
-    public void appendText(String text) {
+    public void appendText(String text, final boolean doNotAppend) {
         if (text == null) {
             return;
         }
-        String previous = this.binding.textinput.getText().toString();
+        final Editable editable = this.binding.textinput.getText();
+        String previous =  editable == null ? "" : editable.toString();
+        if (doNotAppend && !TextUtils.isEmpty(previous)) {
+            Toast.makeText(getActivity(),R.string.already_drafting_message, Toast.LENGTH_LONG).show();
+            return;
+        }
         if (UIHelper.isLastLineQuote(previous)) {
             text = '\n' + text;
         } else if (previous.length() != 0 && !Character.isWhitespace(previous.charAt(previous.length() - 1))) {
```
