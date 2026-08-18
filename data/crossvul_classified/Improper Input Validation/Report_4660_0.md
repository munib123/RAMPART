# CrossVul Fix Pair: Improper Input Validation in csharp
**Pair ID:** 4660_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4660_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```csharp
Lines 7-47 of the vulnerable file.

{
    class Config
    {
        public int PortDef = 21;
        public int PortPasv = 21;
        public string Hostname = "127.0.0.1";
        public string Token = "";
        public string Banner = "Welcome to FTP!";

        public bool Report = true;
        public bool Ban = true;
        public bool PunishScans = true;
        public bool AllowAnonymous = false;
        public bool PerIPLogs = false;

        public int Max_PerSecond = 5;
        public int Max_Total = 6;
        public int BanLength = 3600;
        public int MaxErrors = 6;
        public int BufferSize = 8192;

        

        public List<CJSON_FILE> files;
       

        public Config(string name)
        {
            CJSON json = null;
            string Placeholder = Properties.Resources.ConfigFile;
            try
            {
                if (System.IO.File.Exists(name))
                {
                    string config = System.IO.File.ReadAllText(name);
                    json = JsonConvert.DeserializeObject<CJSON>(config);
                }
                else
                {
                    json = JsonConvert.DeserializeObject<CJSON>(Placeholder);
                    System.IO.File.WriteAllText(name, Placeholder);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -24,6 +24,7 @@
         public int BanLength = 3600;
         public int MaxErrors = 6;
         public int BufferSize = 8192;
+        public int MaxThreads = 50;
 
         
 
@@ -61,6 +62,7 @@
                 MaxErrors = json.MaxErrors;
                 BufferSize = json.BufferSize;
                 PerIPLogs = json.PerIPLogs;
+                MaxThreads = json.MaxThreads;
                 
 
 
@@ -101,6 +103,7 @@
         public int BanLength { get; set; }
         public int MaxErrors { get; set; }
         public int BufferSize { get; set; }
+        public int MaxThreads { get; set; }
         public List<CJSON_FILE> Files { get; set; }
     }
 }
```
