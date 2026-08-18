# CrossVul Fix Pair: Improper Input Validation in java
**Pair ID:** 2626_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2626_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```java
Lines 27-67 of the vulnerable file.


/**
 * The controller for previewing a HtmlForm by loading the xml file that defines that HtmlForm from
 * disk.
 * <p/>
 * Handles {@code htmlFormFromFile.form} requests. Renders view {@code htmlFormFromFile.jsp}.
 */
@Controller
public class HtmlFormFromFileController {
	
	private static final String TEMP_HTML_FORM_FILE_PREFIX = "html_form_";
	
	/** Logger for this class and subclasses */
	protected final Log log = LogFactory.getLog(getClass());
	
	@RequestMapping("/module/htmlformentry/htmlFormFromFile.form")
	public void handleRequest(Model model, @RequestParam(value = "filePath", required = false) String filePath,
	                          @RequestParam(value = "patientId", required = false) Integer pId,
	                          @RequestParam(value = "isFileUpload", required = false) boolean isFileUpload,
	                          HttpServletRequest request) throws Exception {
		
		if (log.isDebugEnabled())
			log.debug("In reference data...");
		
		model.addAttribute("previewHtml", "");
		String message = "";
		File f = null;
		try {
			if (isFileUpload) {
				MultipartHttpServletRequest multipartRequest = (MultipartHttpServletRequest) request;
				MultipartFile multipartFile = multipartRequest.getFile("htmlFormFile");
				if (multipartFile != null) {
					//use the same file for the logged in user
					f = new File(SystemUtils.JAVA_IO_TMPDIR, TEMP_HTML_FORM_FILE_PREFIX
					        + Context.getAuthenticatedUser().getSystemId());
					if (!f.exists())
						f.createNewFile();
					
					filePath = f.getAbsolutePath();
					FileOutputStream fileOut = new FileOutputStream(f);
					IOUtils.copy(multipartFile.getInputStream(), fileOut);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -44,6 +44,8 @@
 	                          @RequestParam(value = "patientId", required = false) Integer pId,
 	                          @RequestParam(value = "isFileUpload", required = false) boolean isFileUpload,
 	                          HttpServletRequest request) throws Exception {
+
+        Context.requirePrivilege("Manage Forms");
 		
 		if (log.isDebugEnabled())
 			log.debug("In reference data...");
```
