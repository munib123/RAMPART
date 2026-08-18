# CrossVul Fix Pair: Improper Input Validation in java
**Pair ID:** 418_3
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `418_3`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```java
Lines 436-476 of the vulnerable file.

		}
	}

	protected boolean usingEnterKey() {
		return getBooleanPreference("display_enter_key", R.bool.display_enter_key);
	}

	protected SharedPreferences getPreferences() {
		return PreferenceManager.getDefaultSharedPreferences(getApplicationContext());
	}

	protected boolean getBooleanPreference(String name, @BoolRes int res) {
		return getPreferences().getBoolean(name, getResources().getBoolean(res));
	}

	public void switchToConversation(Conversation conversation) {
		switchToConversation(conversation, null);
	}

	public void switchToConversationAndQuote(Conversation conversation, String text) {
		switchToConversation(conversation, text, true, null, false);
	}

	public void switchToConversation(Conversation conversation, String text) {
		switchToConversation(conversation, text, false, null, false);
	}

	public void highlightInMuc(Conversation conversation, String nick) {
		switchToConversation(conversation, null, false, nick, false);
	}

	public void privateMsgInMuc(Conversation conversation, String nick) {
		switchToConversation(conversation, null, false, nick, true);
	}

	private void switchToConversation(Conversation conversation, String text, boolean asQuote, String nick, boolean pm) {
		Intent intent = new Intent(this, ConversationsActivity.class);
		intent.setAction(ConversationsActivity.ACTION_VIEW_CONVERSATION);
		intent.putExtra(ConversationsActivity.EXTRA_CONVERSATION, conversation.getUuid());
		if (text != null) {
			intent.putExtra(Intent.EXTRA_TEXT, text);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -453,22 +453,26 @@
 	}
 
 	public void switchToConversationAndQuote(Conversation conversation, String text) {
-		switchToConversation(conversation, text, true, null, false);
+		switchToConversation(conversation, text, true, null, false, false);
 	}
 
 	public void switchToConversation(Conversation conversation, String text) {
-		switchToConversation(conversation, text, false, null, false);
+		switchToConversation(conversation, text, false, null, false, false);
+	}
+
+	public void switchToConversationDoNotAppend(Conversation conversation, String text) {
+		switchToConversation(conversation, text, false, null, false, true);
 	}
 
 	public void highlightInMuc(Conversation conversation, String nick) {
-		switchToConversation(conversation, null, false, nick, false);
+		switchToConversation(conversation, null, false, nick, false, false);
 	}
 
 	public void privateMsgInMuc(Conversation conversation, String nick) {
-		switchToConversation(conversation, null, false, nick, true);
-	}
-
-	private void switchToConversation(Conversation conversation, String text, boolean asQuote, String nick, boolean pm) {
+		switchToConversation(conversation, null, false, nick, true, false);
+	}
+
+	private void switchToConversation(Conversation conversation, String text, boolean asQuote, String nick, boolean pm, boolean doNotAppend) {
 		Intent intent = new Intent(this, ConversationsActivity.class);
 		intent.setAction(ConversationsActivity.ACTION_VIEW_CONVERSATION);
 		intent.putExtra(ConversationsActivity.EXTRA_CONVERSATION, conversation.getUuid());
@@ -481,6 +485,9 @@
 		if (nick != null) {
 			intent.putExtra(ConversationsActivity.EXTRA_NICK, nick);
 			intent.putExtra(ConversationsActivity.EXTRA_IS_PRIVATE_MESSAGE, pm);
+		}
+		if (doNotAppend) {
+			intent.putExtra(ConversationsActivity.EXTRA_DO_NOT_APPEND, true);
 		}
 		intent.setFlags(intent.getFlags() | Intent.FLAG_ACTIVITY_CLEAR_TOP);
 		startActivity(intent);
```
