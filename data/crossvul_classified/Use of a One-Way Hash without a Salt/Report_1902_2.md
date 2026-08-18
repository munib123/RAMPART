# CrossVul Fix Pair: Use of a One-Way Hash without a Salt in java
**Pair ID:** 1902_2
**Vulnerability Class:** Use of a One-Way Hash without a Salt
**CWE:** CWE-759
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1902_2`)

## Vulnerability Information & PoC

## Description
Use of a One-Way Hash without a Salt - This makes it easier for attackers to pre-compute the hash value using dictionary attack techniques such as rainbow tables.

## Vulnerable Code
```java
Lines 4-44 of the vulnerable file.

import java.io.PrintWriter;
import java.util.Random;

import javax.mail.MessagingException;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.bijay.onlinevotingsystem.dao.VoterDao;
import com.bijay.onlinevotingsystem.dao.VoterDaoImpl;

@WebServlet("/vLoginController")
public class VoterLoginController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	VoterDao voterDao = new VoterDaoImpl();
	SHA256 sha = new SHA256();

	private String host;
	private String port;
	private String user;
	private String pass;
	public String recipient;

	public int otp;
	
	public int giveOtp() {
		return this.otp;
	}

	public void init() {
		// reads SMTP server setting from web.xml file
		ServletContext context = getServletContext();
		host = context.getInitParameter("host");
		port = context.getInitParameter("port");
		user = context.getInitParameter("user");
		pass = context.getInitParameter("pass");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -21,7 +21,6 @@
 public class VoterLoginController extends HttpServlet {
 	private static final long serialVersionUID = 1L;
 	VoterDao voterDao = new VoterDaoImpl();
-	SHA256 sha = new SHA256();
 
 	private String host;
 	private String port;
@@ -76,7 +75,7 @@
 		otp = r.nextInt(max - min) + min;
 
 		String userName = request.getParameter("uname");
-		String password = sha.getSHA(request.getParameter("pass"));
+		String password = request.getParameter("pass");
 		String vemail = request.getParameter("vmail");
 
 		String recipient = vemail;
```
