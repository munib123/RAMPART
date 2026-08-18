# CrossVul Fix Pair: Reliance on Reverse DNS Resolution for a Security-Critical Action in go
**Pair ID:** 3948_2
**Vulnerability Class:** Reliance on Reverse DNS Resolution for a Security-Critical Action
**CWE:** CWE-350
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3948_2`)

## Vulnerability Information & PoC

## Description
Reliance on Reverse DNS Resolution for a Security-Critical Action - Since DNS names can be easily spoofed or misreported, and it may be difficult for the product to detect if a trusted DNS server has been compromised, DNS names do not constitute a valid authenticat...

## Vulnerable Code
```go
Lines 1-36 of the vulnerable file.

package net

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/j-keck/arping"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// create and attach a veth to the Weave bridge
func CreateAndAttachVeth(name, peerName, bridgeName string, mtu int, keepTXOn bool, errIfLinkExist bool, init func(peer netlink.Link) error) (*netlink.Veth, error) {
	bridge, err := netlink.LinkByName(bridgeName)
	if err != nil {
		return nil, fmt.Errorf(`bridge "%s" not present; did you launch weave?`, bridgeName)
	}

	if mtu == 0 {
		mtu = bridge.Attrs().MTU
	}
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: name,
			MTU:  mtu},
		PeerName: peerName,
	}

	linkAdd := LinkAddIfNotExist
	if errIfLinkExist {
		linkAdd = netlink.LinkAdd
	}
	if err := linkAdd(veth); err != nil {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,7 +13,7 @@
 )
 
 // create and attach a veth to the Weave bridge
-func CreateAndAttachVeth(name, peerName, bridgeName string, mtu int, keepTXOn bool, errIfLinkExist bool, init func(peer netlink.Link) error) (*netlink.Veth, error) {
+func CreateAndAttachVeth(procPath, name, peerName, bridgeName string, mtu int, keepTXOn bool, errIfLinkExist bool, init func(peer netlink.Link) error) (*netlink.Veth, error) {
 	bridge, err := netlink.LinkByName(bridgeName)
 	if err != nil {
 		return nil, fmt.Errorf(`bridge "%s" not present; did you launch weave?`, bridgeName)
@@ -49,6 +49,13 @@
 	if err := bridgeType.attach(veth); err != nil {
 		return cleanup("attaching veth %q to %q: %s", name, bridgeName, err)
 	}
+	// No ipv6 router advertisments please
+	if err := sysctl(procPath, "net/ipv6/conf/"+name+"/accept_ra", "0"); err != nil {
+		return cleanup("setting accept_ra to 0: %s", err)
+	}
+	if err := sysctl(procPath, "net/ipv6/conf/"+peerName+"/accept_ra", "0"); err != nil {
+		return cleanup("setting accept_ra to 0: %s", err)
+	}
 	if !bridgeType.IsFastdp() && !keepTXOn {
 		if err := EthtoolTXOff(veth.PeerName); err != nil {
 			return cleanup(`unable to set tx off on %q: %s`, peerName, err)
@@ -112,6 +119,9 @@
 }
 
 func AttachContainer(netNSPath, id, ifName, bridgeName string, mtu int, withMulticastRoute bool, cidrs []*net.IPNet, keepTXOn bool, hairpinMode bool) error {
+	// AttachContainer expects to be called in host pid namespace
+	const procPath = "/proc"
+
 	ns, err := netns.GetFromPath(netNSPath)
 	if err != nil {
 		return err
@@ -124,12 +134,12 @@
 			id = id[:maxIDLen] // trim passed ID if too long
 		}
 		name, peerName := vethPrefix+"pl"+id, vethPrefix+"pg"+id
-		veth, err := CreateAndAttachVeth(name, peerName, bridgeName, mtu, keepTXOn, true, func(veth netlink.Link) error {
+		veth, err := CreateAndAttachVeth(procPath, name, peerName, bridgeName, mtu, keepTXOn, true, func(veth netlink.Link) error {
 			if err := netlink.LinkSetNsFd(veth, int(ns)); err != nil {
 				return fmt.Errorf("failed to move veth to container netns: %s", err)
 			}
 			if err := WithNetNS(ns, func() error {
-				return setupIface(peerName, ifName)
+				return setupIface(procPath, peerName, ifName)
 			}); err != nil {
 				return fmt.Errorf("error setting up interface: %s", err)
 			}
@@ -206,7 +216,7 @@
 }
 
 // setupIface expects to be called in the container's netns
-func setupIface(ifaceName, newIfName string) error {
+func setupIface(procPath, ifaceName, newIfName string) error {
 	ipt, err := iptables.New()
 	if err != nil {
 		return err
@@ -219,15 +229,14 @@
 	if err := netlink.LinkSetName(link, newIfName); err != nil {
 		return err
 	}
-	// This is only called by AttachContainer which is only called in host pid namespace
-	if err := configureARPCache("/proc", newIfName); err != nil {
+	if err := configureARPCache(procPath, newIfName); err != nil {
 		return err
 	}
 	return ipt.Append("filter", "INPUT", "-i", newIfName, "-d", "224.0.0.0/4", "-j", "DROP")
 }
 
 // configureARP is a helper for the Docker plugin which doesn't set the addresses itself
-func ConfigureARP(prefix, rootPath string) error {
+func ConfigureARP(prefix, procPath string) error {
 	links, err := netlink.LinkList()
 	if err != nil {
 		return err
@@ -235,7 +244,7 @@
 	for _, link := range links {
 		ifName := link.Attrs().Name
 		if strings.HasPrefix(ifName, prefix) {
-			configureARPCache(rootPath+"/proc", ifName)
+			configureARPCache(procPath, ifName)
 			if addrs, err := netlink.AddrList(link, netlink.FAMILY_V4); err == nil {
 				for _, addr := range addrs {
 					arping.GratuitousArpOverIfaceByName(addr.IPNet.IP, ifName)
```
