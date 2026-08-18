# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 2312_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2312_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 5381-5421 of the vulnerable file.


    gettimeofday( &tv, NULL );
    i=0;

    while (1)  //waiting for GET_CHAN answer
    {
        caplen = read(sock, &nh, sizeof(nh));

        if(caplen == -1)
        {
            if( errno != EAGAIN )
            {
                perror("read");
                return -1;
            }
        }

        if( (unsigned)caplen == sizeof(nh))
        {
            len = ntohl(nh.nh_len);
            if( nh.nh_type == 1 && i==0 )
            {
                i=1;
                caplen = read(sock, packet, len);
                if(caplen == len)
                {
                    i=2;
                    break;
                }
                else
                {
                    i=0;
                }
            }
            else
            {
                caplen = read(sock, packet, len);
            }
        }

        gettimeofday( &tv2, NULL );
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5398,6 +5398,8 @@
         if( (unsigned)caplen == sizeof(nh))
         {
             len = ntohl(nh.nh_len);
+            if (len > 1024 || len < 0)
+                continue;
             if( nh.nh_type == 1 && i==0 )
             {
                 i=1;
```
