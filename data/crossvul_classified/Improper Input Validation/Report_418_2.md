# CrossVul Fix Pair: Improper Input Validation in java
**Pair ID:** 418_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `418_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```java
Lines 470-510 of the vulnerable file.

				prefilledJid,
				null,
				invite == null || !invite.hasFingerprints()
		);

		dialog.setOnEnterJidDialogPositiveListener((accountJid, contactJid) -> {
			if (!xmppConnectionServiceBound) {
				return false;
			}

			final Account account = xmppConnectionService.findAccountByJid(accountJid);
			if (account == null) {
				return true;
			}

			final Contact contact = account.getRoster().getContact(contactJid);
			if (invite != null && invite.getName() != null) {
				contact.setServerName(invite.getName());
			}
			if (contact.isSelf()) {
				switchToConversation(contact, null);
				return true;
			} else if (contact.showInRoster()) {
				throw new EnterJidDialog.JidError(getString(R.string.contact_already_exists));
			} else {
				xmppConnectionService.createContact(contact, true);
				if (invite != null && invite.hasFingerprints()) {
					xmppConnectionService.verifyFingerprints(contact, invite.getFingerprints());
				}
				switchToConversation(contact, invite == null ? null : invite.getBody());
				return true;
			}
		});
		dialog.show(ft, FRAGMENT_TAG_DIALOG);
	}

	@SuppressLint("InflateParams")
	protected void showJoinConferenceDialog(final String prefilledJid) {
		FragmentTransaction ft = getSupportFragmentManager().beginTransaction();
		Fragment prev = getSupportFragmentManager().findFragmentByTag(FRAGMENT_TAG_DIALOG);
		if (prev != null) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -487,7 +487,7 @@
 				contact.setServerName(invite.getName());
 			}
 			if (contact.isSelf()) {
-				switchToConversation(contact, null);
+				switchToConversation(contact);
 				return true;
 			} else if (contact.showInRoster()) {
 				throw new EnterJidDialog.JidError(getString(R.string.contact_already_exists));
@@ -496,7 +496,7 @@
 				if (invite != null && invite.hasFingerprints()) {
 					xmppConnectionService.verifyFingerprints(contact, invite.getFingerprints());
 				}
-				switchToConversation(contact, invite == null ? null : invite.getBody());
+				switchToConversationDoNotAppend(contact, invite == null ? null : invite.getBody());
 				return true;
 			}
 		});
@@ -543,11 +543,14 @@
 		return xmppConnectionService.findAccountByJid(jid);
 	}
 
-	protected void switchToConversation(Contact contact, String body) {
-		Conversation conversation = xmppConnectionService
-				.findOrCreateConversation(contact.getAccount(),
-						contact.getJid(), false, true);
-		switchToConversation(conversation, body);
+	protected void switchToConversation(Contact contact) {
+		Conversation conversation = xmppConnectionService.findOrCreateConversation(contact.getAccount(), contact.getJid(), false, true);
+		switchToConversation(conversation);
+	}
+
+	protected void switchToConversationDoNotAppend(Contact contact, String body) {
+		Conversation conversation = xmppConnectionService.findOrCreateConversation(contact.getAccount(), contact.getJid(), false, true);
+		switchToConversationDoNotAppend(conversation, body);
 	}
 
 	@Override
@@ -777,7 +780,7 @@
 		if (invite.isAction(XmppUri.ACTION_JOIN)) {
 			Conversation muc = xmppConnectionService.findFirstMuc(invite.getJid());
 			if (muc != null) {
-				switchToConversation(muc, invite.getBody());
+				switchToConversationDoNotAppend(muc, invite.getBody());
 				return true;
 			} else {
 				showJoinConferenceDialog(invite.getJid().asBareJid().toString());
@@ -799,7 +802,7 @@
 				if (invite.account != null) {
 					xmppConnectionService.getShortcutService().report(contact);
 				}
-				switchToConversation(contact, invite.getBody());
+				switchToConversationDoNotAppend(contact, invite.getBody());
 			}
 			return true;
 		} else {
@@ -827,7 +830,7 @@
 			if (isTrustedSource.isChecked() && invite.hasFingerprints()) {
 				xmppConnectionService.verifyFingerprints(contact, invite.getFingerprints());
 			}
-			switchToConversation(contact, invite.getBody());
+			switchToConversationDoNotAppend(contact, invite.getBody());
 		});
 		builder.setNegativeButton(R.string.cancel, (dialog, which) -> StartConversationActivity.this.finish());
 		AlertDialog dialog = builder.create();
```
