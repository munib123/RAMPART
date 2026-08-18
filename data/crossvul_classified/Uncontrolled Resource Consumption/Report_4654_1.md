# CrossVul Fix Pair: Uncontrolled Resource Consumption in csharp
**Pair ID:** 4654_1
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4654_1`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```csharp
Lines 25-65 of the vulnerable file.

        public static bool Report = true;
        public static bool Ban = true;
        public static bool PunishScans = true;

        //IP TempBan list (hostname:seconds)
        public static List<Ban> bans = new List<Ban>();

        //An instance of config to extract values
        public static Config config;

        //Used because everybody likes random numbers.
        public static Random rnd = new Random();
        public static readonly HttpClient client = new HttpClient();
        //List of all connected (to main port) clients
        public static List<Client> connected = new List<Client>();

        //Default directory. TODO: Implement directories
        public static Directory root = new Directory();

        //Current version
        public static string _VERSION = "v0.1.0 BETA";

        //Default log.
        public static StreamWriter logfile = new StreamWriter("log.txt", true);

        //Dictionary of passvie clients (clients with PASV mode. Used to communicate directly later.)
        public static Dictionary<Client, Connectivity> passives = new Dictionary<Client, Connectivity>();

        /// <summary>
        /// Reports an IP
        /// </summary>
        /// <param name="hostname">IP to report</param>
        /// <param name="comment">Logs or comments regarding report</param>
        /// <param name="hacking">Is accused in hacking?</param>
        /// <param name="brute">Is accused in bruting?</param>
        /// <param name="webapp_h">Is accused in webapp hacking?</param>
        /// <param name="scanning">Is accused in portscanning?</param>
        /// <param name="ddos">Is accused in DDoS</param>
        /// <returns>A task to execute</returns>
        public static async System.Threading.Tasks.Task ReportAsync(string hostname, string comment, bool hacking, bool brute, bool webapp_h, bool scanning, bool ddos)
        {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -42,13 +42,21 @@
         public static Directory root = new Directory();
 
         //Current version
-        public static string _VERSION = "v0.1.0 BETA";
+        public static string _VERSION = "v0.2.0 BETA";
 
         //Default log.
         public static StreamWriter logfile = new StreamWriter("log.txt", true);
 
         //Dictionary of passvie clients (clients with PASV mode. Used to communicate directly later.)
         public static Dictionary<Client, Connectivity> passives = new Dictionary<Client, Connectivity>();
+
+        //List of connections per second from hostname
+        public static List<Active> per_second = new List<Active>();
+        //List of overall connections from hostname
+        public static List<Active> actives = new List<Active>();
+
+        //List of overall connections to PASV
+        public static List<Active> pasv_actives = new List<Active>();
 
         /// <summary>
         /// Reports an IP
@@ -296,6 +304,23 @@
                     }
                 }
             })).Start();
+            //Connections per seconds (antibot) handling
+            new Thread(new ThreadStart(() => {
+                Thread.CurrentThread.IsBackground = true;
+
+                while (true)
+                {
+                    Thread.Sleep(1000);
+                    for (int i = 0; i < per_second.Count; i++)
+                    {
+                        if (per_second[i].connected > 0)
+                        {
+                            per_second[i].connected -= 1;
+                        }
+                    }
+                 //   Console.WriteLine("[DBG] Iterated per_second!");
+                }
+            })).Start();
             ftp.Start();
             pasv.Start();
             new Thread(() =>
@@ -312,6 +337,53 @@
                     StreamWriter sw = new StreamWriter(ns);
 
                     sw.AutoFlush = true;
+                    string hostname = ((IPEndPoint)client.Client.RemoteEndPoint).Address.ToString();
+                    if (Active.CheckExists(hostname, actives))
+                    {
+                        if (Active.GetConnections(hostname, actives) >= 5)
+                        {
+                            client.Close();
+                            if (Ban)
+                            {
+                                var aaa = new Ban();
+                                aaa.hostname = hostname;
+                                aaa.time = 3600;
+                                bans.Add(aaa);
+                            }
+                        }
+                        else
+                        {
+                            Active.SetConnections(hostname, actives, Active.GetConnections(hostname, actives) + 1);
+                        }
+                    }
+                    else
+                    {
+                        actives.Add(new Active(hostname, 1));
+                    }
+
+                    if (Active.CheckExists(hostname, per_second))
+                    {
+                        if (Active.GetConnections(hostname, per_second) >= 5)
+                        {
+                            client.Close();
+                            if (Ban)
+                            {
+                                var aaa = new Ban();
+                                aaa.hostname = hostname;
+                                aaa.time = 3600;
+                                bans.Add(aaa);
+                            }
+                        }
+                        else
+                        {
+                            Active.SetConnections(hostname, per_second, Active.GetConnections(hostname, per_second) + 1);
+                        }
+                    }
+                    else
+                    {
+                        per_second.Add(new Active(hostname, 1));
+                       
+                    }
 
                     new Thread(new ThreadStart(() =>
                     {
@@ -325,9 +397,9 @@
                         string directory = "/";
                         bool Authed = false;
                         bool passive = false;
-                        int error = 10;
-                        string hostname = ((IPEndPoint)client.Client.RemoteEndPoint).Address.ToString();
+                        int error = 5;
                         
+
                         //AbuseDBIP.com API
                         bool hacking = false;
                         bool bruteforce = false;
@@ -343,25 +415,26 @@
                                 client.Close();
                             }
                         }
-                        catch { 
-
-                        }
-
-
+                        catch
+                        {
+
+                        }
+
+                        
 
                         try
                         {
                             Thread.Sleep(100);
                             Log("Connected - " + hostname, "in", true, hostname);
-                            LogWrite("220 "+config.Banner.Replace("%host%", Hostname)+"\r\n", sw, hostname);
-                            
+                            LogWrite("220 " + config.Banner.Replace("%host%", Hostname) + "\r\n", sw, hostname);
+
                             while (client.Connected)
                             {
                                 Thread.Sleep(100);
                                 //Receiving handler START
                                 string answ = "";
                                 bool flag = true;
-                                
+
                                 while (flag)
                                 {
                                     int a = sr.Read();
@@ -379,7 +452,7 @@
                                 //Receiving handler END
 
                                 //Command processing.
-                                if (answ.Length > 3) //We dont want dummies to spam/DDoS.
+                                if (answ.Length >= 3) //We dont want dummies to spam/DDoS.
                                 {
                                     Log(answ, "in", true, hostname);
                                 }
@@ -393,12 +466,12 @@
                                         bans.Add(aaa);
                                         client.Close();
                                     }
-                                    var a = ReportAsync(hostname, "["+DateTime.Now.ToString("MM/dd/yyyy HH:mm:ss") + "] " + "System scanning (Proxy judging) using CONNECT or GET requests", false, false, true, true, false);
+                                    var a = ReportAsync(hostname, "[" + DateTime.Now.ToString("MM/dd/yyyy HH:mm:ss") + "] " + "System scanning (Proxy judging) using CONNECT or GET requests", false, false, true, true, false);
                                     a.Start();
-                                    
-                                    
-                                }
-                                if (answ.Length > 64)
+
+
+                                }
+                                if (answ.Length > 128)
                                 {
                                     client.Close();
                                 }
@@ -549,7 +622,7 @@
                                             LogWrite("150 Ok to send data.\r\n", sw, hostname);
                                             Thread.Sleep(100);
                                             //       byte[] file = aaaa.content;
-                                           //Encoding.ASCII.GetChars(file);
+                                            //Encoding.ASCII.GetChars(file);
                                             //      connn.sw.Write(chars, 0, file.Length);
                                             //      connn.tcp.Close();
                                             SendFile(aaaa, connn.sw);
@@ -678,10 +751,14 @@
                                 }
... (diff truncated)
```
