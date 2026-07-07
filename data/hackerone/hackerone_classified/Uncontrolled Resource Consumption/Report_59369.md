# HackerOne Report: Making any Report Failed to load
**Report ID:** 59369
**Vulnerability Class:** Uncontrolled Resource Consumption

## Vulnerability Information & PoC
Hello,

I found a way to make any report failed to load using this code with Hex Character:
```_www.%40ebаy.com_ ```

I was testing for Homographic Issue using Hex Characters and I listed all of hex character and tried to bypass. 

Then, when I paste the list and comment it in a report I experienced report failed to load then I paste each code with hex character one by one. I figured out that ```%40``` causes the report failed to load.

To reproduce this issue:
- Create a sample report then add a comment using the code above.
- Then, Refresh and you will receive a message ```Report Failed to load```

Regards,
@atom

## Discussion & Remediation Timeline
