# CrossVul Fix Pair: Improperly Controlled Modification of Dynamically-Determined Object Attributes in java
**Pair ID:** 1997_0
**Vulnerability Class:** Modification of Assumed-Immutable Data (MAID)
**CWE:** CWE-915
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1997_0`)

## Vulnerability Information & PoC

## Description
Improperly Controlled Modification of Dynamically-Determined Object Attributes - If the object contains attributes that were only intended for internal use, then their unexpected modification could lead to a vulnerability.

## Vulnerable Code
```java
Lines 86-127 of the vulnerable file.

	private StatsService statsService;

	@Autowired
	private RedirectResolver redirectResolver;

	/**
	 * Logger for this class
	 */
	private static final Logger logger = LoggerFactory.getLogger(OAuthConfirmationController.class);

	public OAuthConfirmationController() {

	}

	public OAuthConfirmationController(ClientDetailsEntityService clientService) {
		this.clientService = clientService;
	}

	@PreAuthorize("hasRole('ROLE_USER')")
	@RequestMapping("/oauth/confirm_access")
	public String confimAccess(Map<String, Object> model, @ModelAttribute("authorizationRequest") AuthorizationRequest authRequest,
			Principal p) {

		// Check the "prompt" parameter to see if we need to do special processing

		String prompt = (String)authRequest.getExtensions().get(PROMPT);
		List<String> prompts = Splitter.on(PROMPT_SEPARATOR).splitToList(Strings.nullToEmpty(prompt));
		ClientDetailsEntity client = null;

		try {
			client = clientService.loadClientByClientId(authRequest.getClientId());
		} catch (OAuth2Exception e) {
			logger.error("confirmAccess: OAuth2Exception was thrown when attempting to load client", e);
			model.put(HttpCodeView.CODE, HttpStatus.BAD_REQUEST);
			return HttpCodeView.VIEWNAME;
		} catch (IllegalArgumentException e) {
			logger.error("confirmAccess: IllegalArgumentException was thrown when attempting to load client", e);
			model.put(HttpCodeView.CODE, HttpStatus.BAD_REQUEST);
			return HttpCodeView.VIEWNAME;
		}

		if (client == null) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -103,9 +103,9 @@
 
 	@PreAuthorize("hasRole('ROLE_USER')")
 	@RequestMapping("/oauth/confirm_access")
-	public String confimAccess(Map<String, Object> model, @ModelAttribute("authorizationRequest") AuthorizationRequest authRequest,
-			Principal p) {
-
+	public String confirmAccess(Map<String, Object> model, Principal p) {
+
+		AuthorizationRequest authRequest = (AuthorizationRequest) model.get("authorizationRequest");
 		// Check the "prompt" parameter to see if we need to do special processing
 
 		String prompt = (String)authRequest.getExtensions().get(PROMPT);
```
