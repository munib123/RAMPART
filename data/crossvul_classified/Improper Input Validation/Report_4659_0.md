# CrossVul Fix Pair: Improper Input Validation in csharp
**Pair ID:** 4659_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4659_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```csharp
Lines 478-537 of the vulnerable file.

                        bool hacking = false;
                        bool bruteforce = false;
                        bool webapp = false;
                        string comment = "";


                        bool banned = false;
                        

                        

                        try
                        {
                            Thread.Sleep(100);
                            Log("Connected - " + hostname, "in", true, hostname, perip);
                            LogWrite("220 " + Banner.Replace("%host%", Hostname) + "\r\n", sw, hostname, perip);

                            while (client.Connected)
                            {
                                Thread.Sleep(100);
                                //Receiving handler START
                                string answ = "";
                                bool flag = true;
                                bool upper = true;

                                while (flag)
                                {
                                    int a = sr.Read();
                                    if (upper)
                                    {
                                        answ += char.ToUpper((char)a);
                                    } else
                                    {
                                        answ += (char)a;
                                    }
                                    if (a == 13)
                                    {
                                        flag = false;
                                    }
                                    if (a == 0x20)
                                    {
                                        upper = false;
                                    }
                                    if (answ.Length > 128)
                                    {
                                        client.Close();
                                    }
                                }
                                answ = answ.Trim();
                                //Receiving handler END

                                //Command processing.
                                if (answ.Length >= 3) //We dont want dummies to spam/DDoS.
                                {
                                    Log(answ, "in", true, hostname, perip);
                                }
                                if (answ.StartsWith("CONNECT") || answ.StartsWith("GET http"))
                                {
                                    if (Ban)
                                    {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -495,36 +495,12 @@
                             while (client.Connected)
                             {
                                 Thread.Sleep(100);
-                                //Receiving handler START
-                                string answ = "";
-                                bool flag = true;
-                                bool upper = true;
-
-                                while (flag)
-                                {
-                                    int a = sr.Read();
-                                    if (upper)
-                                    {
-                                        answ += char.ToUpper((char)a);
-                                    } else
-                                    {
-                                        answ += (char)a;
-                                    }
-                                    if (a == 13)
-                                    {
-                                        flag = false;
-                                    }
-                                    if (a == 0x20)
-                                    {
-                                        upper = false;
-                                    }
-                                    if (answ.Length > 128)
-                                    {
-                                        client.Close();
-                                    }
-                                }
-                                answ = answ.Trim();
-                                //Receiving handler END
+                                
+                                string answ = sr.ReadLine(); //Who'd think this ACTUALLY works. BUT: It's doesnt work on Linux? (Needs testing)
+                                //Tested on Ubuntu 16.04 client and 18.04 server. Seems to work!
+                         
+                                string upperfix = answ.Split(' ')[0].ToUpper();
+                                answ.Replace(answ.Split(' ')[0], upperfix); //Fixing the lowercase commands an easy way
 
                                 //Command processing.
                                 if (answ.Length >= 3) //We dont want dummies to spam/DDoS.
@@ -558,7 +534,7 @@
                                 {
                                     string temp = answ.Substring(5).Trim();
                                     Regex r = new Regex("^[a-zA-Z0-9]*$");
-                                    if (r.IsMatch(temp) && temp.Length < 32 && temp.Length > 1 && (temp != "anonymous" && !AllowAnonymous))
+                                    if (r.IsMatch(temp) && temp.Length < 32 && temp.Length > 1 && (temp != "anonymous" || AllowAnonymous))
                                     {
                                         username = temp;
                                         LogWrite("331 This user is protected with password\r\n", sw, hostname, perip);
@@ -644,16 +620,16 @@
                                             LogWrite("150 Ok to send data.\r\n", sw, hostname, perip);
                                             Thread.Sleep(100);
                                             List<byte> filess = new List<byte>();
-                                            var bytes = default(byte[]);
+                                            var bytess = default(byte[]);
                                             using (var memstream = new MemoryStream())
                                             {
                                                 var buffer = new byte[512];
                                                 var bytesRead = default(int);
                                                 while ((bytesRead = connn.sr.BaseStream.Read(buffer, 0, buffer.Length)) > 0)
                                                     memstream.Write(buffer, 0, bytesRead);
-                                                bytes = memstream.ToArray();
+                                                bytess = memstream.ToArray();
                                             }
-                                            System.IO.File.WriteAllBytes("dumps/dump_i" + rnd.Next(1, 2000000000).ToString() + ".txt", bytes);
+                                            System.IO.File.WriteAllBytes("dumps/dump_i" + rnd.Next(1, 2000000000).ToString() + ".txt", bytess);
                                             Thread.Sleep(200);
                                             LogWrite("226 Transfer complete!\r\n", sw, hostname, perip);
 
```
