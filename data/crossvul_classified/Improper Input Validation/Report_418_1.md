# CrossVul Fix Pair: Improper Input Validation in java
**Pair ID:** 418_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `418_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```java
Lines 75-115 of the vulnerable file.

import eu.siacs.conversations.ui.util.ActivityResult;
import eu.siacs.conversations.ui.util.ConversationMenuConfigurator;
import eu.siacs.conversations.ui.util.MenuDoubleTabUtil;
import eu.siacs.conversations.ui.util.PendingItem;
import eu.siacs.conversations.utils.EmojiWrapper;
import eu.siacs.conversations.utils.ExceptionHelper;
import eu.siacs.conversations.utils.XmppUri;
import eu.siacs.conversations.xmpp.OnUpdateBlocklist;
import rocks.xmpp.addr.Jid;

import static eu.siacs.conversations.ui.ConversationFragment.REQUEST_DECRYPT_PGP;

public class ConversationsActivity extends XmppActivity implements OnConversationSelected, OnConversationArchived, OnConversationsListItemUpdated, OnConversationRead, XmppConnectionService.OnAccountUpdate, XmppConnectionService.OnConversationUpdate, XmppConnectionService.OnRosterUpdate, OnUpdateBlocklist, XmppConnectionService.OnShowErrorToast, XmppConnectionService.OnAffiliationChanged, XmppConnectionService.OnRoleChanged {

    public static final String ACTION_VIEW_CONVERSATION = "eu.siacs.conversations.action.VIEW";
    public static final String EXTRA_CONVERSATION = "conversationUuid";
    public static final String EXTRA_DOWNLOAD_UUID = "eu.siacs.conversations.download_uuid";
    public static final String EXTRA_AS_QUOTE = "as_quote";
    public static final String EXTRA_NICK = "nick";
    public static final String EXTRA_IS_PRIVATE_MESSAGE = "pm";

    private static List<String> VIEW_AND_SHARE_ACTIONS = Arrays.asList(
            ACTION_VIEW_CONVERSATION,
            Intent.ACTION_SEND,
            Intent.ACTION_SEND_MULTIPLE
    );

    public static final int REQUEST_OPEN_MESSAGE = 0x9876;
    public static final int REQUEST_PLAY_PAUSE = 0x5432;


    //secondary fragment (when holding the conversation, must be initialized before refreshing the overview fragment
    private static final @IdRes
    int[] FRAGMENT_ID_NOTIFICATION_ORDER = {R.id.secondary_fragment, R.id.main_fragment};
    private final PendingItem<Intent> pendingViewIntent = new PendingItem<>();
    private final PendingItem<ActivityResult> postponedActivityResult = new PendingItem<>();
    private ActivityConversationsBinding binding;
    private boolean mActivityPaused = true;
    private AtomicBoolean mRedirectInProcess = new AtomicBoolean(false);

    private static boolean isViewOrShareIntent(Intent i) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -92,6 +92,7 @@
     public static final String EXTRA_AS_QUOTE = "as_quote";
     public static final String EXTRA_NICK = "nick";
     public static final String EXTRA_IS_PRIVATE_MESSAGE = "pm";
+    public static final String EXTRA_DO_NOT_APPEND = "do_not_append";
 
     private static List<String> VIEW_AND_SHARE_ACTIONS = Arrays.asList(
             ACTION_VIEW_CONVERSATION,
```
