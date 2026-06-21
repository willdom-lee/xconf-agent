package driver

import (
	"fmt"
	"math/rand"
	"strings"
	"time"
	"xconf-agent/config"
)

// MockDriver retrieves a dynamic, realistic-looking switch configuration for testing
type MockDriver struct{}

func (m *MockDriver) FetchConfig(dev *config.Device) ([]byte, error) {
	vendor := strings.ToLower(dev.Vendor)
	cleanName := strings.ReplaceAll(dev.Name, " ", "-")
	
	// Create some unique values based on the last 4 characters of the ID
	idSuffix := "default"
	if len(dev.ID) > 4 {
		idSuffix = dev.ID[len(dev.ID)-4:]
	}
	
	// Format dynamic IPs and VLANs based on the suffix to ensure configurations are unique
	vlanId := 10 + (int(idSuffix[0]) % 5) * 5
	ipSuffix := 10 + (int(idSuffix[len(idSuffix)-1]) % 200)

	// Seed random generator with current time nanoseconds to generate configuration variations
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	if vendor == "h3c" || vendor == "huawei" {
		// Dynamic variations for H3C
		h3cChangeLog := fmt.Sprintf("# Last configuration change by admin at %s", time.Now().Format("2006-01-02 15:04:05"))
		
		h3cLoopback := ""
		if r.Float32() > 0.4 {
			h3cLoopback = fmt.Sprintf("\ninterface Loopback0\n description Test_Diagnostic_Loopback\n ip address 10.%d.254.1 255.255.255.255\n#", r.Intn(250)+1)
		}

		h3cGig5Desc := "User Workstation (Auto-assigned)"
		h3cGig5Shutdown := ""
		switch r.Intn(4) {
		case 1:
			h3cGig5Desc = "User Workstation (Accounting Dept)"
		case 2:
			h3cGig5Desc = "User Workstation (Marketing Dept)"
			h3cGig5Shutdown = "\n shutdown"
		case 3:
			h3cGig5Desc = "User Workstation (Development Dept)"
		}

		return []byte(fmt.Sprintf(`#
# H3C Comware Software, Version 7.1.070, Release 7536P05
# Copyright (c) 2004-2026 New H3C Technologies Co., Ltd. All rights reserved.
#
%s
sysname %s
#
 vlan %d
  description OOB_Management_%s
#
 vlan %d
  description User_Data_VLAN_%s
#
 vlan %d
  description VoIP_Phones_%s
#
 vlan 100
  description Server_Farm_Zone
#
stp global enable
stp mode rstp
#
dns server 8.8.8.8
dns server 1.1.1.1
#
local-user admin class manage
 password simple $6$jXz5wQ9r$HjKw29s8aB83cK8d98d1a
 service-type ssh telnet terminal
 authorization-attribute user-role network-admin
#
local-user operator class manage
 password simple $6$mPs2wY5t$PlKq83u7sB94dJ8e98f2c
 service-type ssh
 authorization-attribute user-role network-operator
#
interface GigabitEthernet1/0/1
 port link-mode route
 ip address %s 255.255.255.252
 ospf 1 area 0.0.0.0
#
interface GigabitEthernet1/0/2
 description Link to Core-Switch-1
 port link-mode bridge
 port link-type trunk
 port trunk permit vlan 10 20 30 100
 port trunk pvid vlan %d
 stp edged-port disable
#
interface GigabitEthernet1/0/3
 description Link to Core-Switch-2
 port link-mode bridge
 port link-type trunk
 port trunk permit vlan 10 20 30 100
 port trunk pvid vlan %d
 stp edged-port disable
#
interface GigabitEthernet1/0/4
 description Link to Server_Rack_02
 port link-mode bridge
 port link-type trunk
 port trunk permit vlan 100
#
interface GigabitEthernet1/0/5
 description %s
 port link-mode bridge
 port access vlan %d
 stp edged-port enable%s
#
interface GigabitEthernet1/0/6
 description VoIP Desk Phone
 port link-mode bridge
 port access vlan %d
 voice vlan %d enable
 stp edged-port enable
#%s
interface Vlan-interface%d
 description Out-of-band Management Interface
 ip address 10.254.%d.2 255.255.255.0
 dhcp select relay
 dhcp relay server-address 10.100.1.5
#
interface Vlan-interface%d
 description Gateway for User Data
 ip address 10.%d.2.1 255.255.255.0
 dhcp select relay
 dhcp relay server-address 10.100.1.5
#
ospf 1 router-id 10.254.1.2
 area 0.0.0.0
  network 10.%d.2.0 0.0.0.255
  network 10.254.%d.0 0.0.0.255
#
ip route-static 0.0.0.0 0.0.0.0 10.254.1.2
#
acl basic 2000
 rule 0 permit source 10.254.%d.0 0.0.0.255
 rule 5 deny source any
#
info-center loghost syslog.enterprise.local
snmp-agent community read public
snmp-agent sys-info contact Network_Operations_Center
#
ssh server enable
#
user-interface aux 0
user-interface vty 0 4
 acl 2000 inbound
 authentication-mode scheme
 protocol inbound ssh
#
return`, 
			h3cChangeLog,
			cleanName, 
			vlanId, idSuffix, 
			vlanId+10, idSuffix, 
			vlanId+20, idSuffix, 
			dev.IP, 
			vlanId, 
			vlanId, 
			h3cGig5Desc,
			vlanId,
			h3cGig5Shutdown,
			vlanId+10, 
			vlanId+20, 
			h3cLoopback,
			vlanId, ipSuffix, 
			vlanId+10, ipSuffix, 
			ipSuffix, vlanId, 
			vlanId,
		)), nil
	}

	// Dynamic variations for Cisco
	configChangeLog := fmt.Sprintf("! Last configuration change by admin at %s", time.Now().Format("2006-01-02 15:04:05"))
	
	loopback0 := ""
	if r.Float32() > 0.4 {
		loopback0 = fmt.Sprintf("\ninterface Loopback0\n description Diagnostic Loopback\n ip address 10.%d.254.1 255.255.255.255\n!", r.Intn(250)+1)
	}

	gig5Desc := "User Workstation (Auto-assigned)"
	gig5Shutdown := ""
	switch r.Intn(4) {
	case 1:
		gig5Desc = "User Workstation (Finance Dept)"
	case 2:
		gig5Desc = "User Workstation (HR Dept)"
		gig5Shutdown = "\n shutdown"
	case 3:
		gig5Desc = "User Workstation (Engineering Dept)"
	}

	syslogIP := "syslog.enterprise.local"
	if r.Float32() > 0.5 {
		syslogIP = fmt.Sprintf("10.100.1.%d", r.Intn(100)+10)
	}

	vlan100Name := "Server_Farm_Zone"
	if r.Float32() > 0.6 {
		vlan100Name = "DMZ_External_Zone"
	}

	// Default to Cisco format
	return []byte(fmt.Sprintf(`! Cisco IOS Software, Catalyst L3 Switch Software
! Technical Support: http://www.cisco.com/techsupport
!
%s
version 15.2
service timestamps debug datetime msec
service timestamps log datetime msec
service password-encryption
!
hostname %s
!
boot-start-marker
boot-end-marker
!
enable password cipher 7 0822455R31
enable secret 5 $1$mERr$hx5qzG3z/02394832
!
username admin privilege 15 password cipher 7 0822455R31
username operator privilege 5 password cipher 7 0922415R33
!
vlan %d
 name OOB_Management_%s
!
vlan %d
 name User_Data_VLAN_%s
!
vlan %d
 name VoIP_Phones_%s
!
vlan 100
 name %s
!
ip routing
ip domain-name enterprise.local
ip name-server 8.8.8.8 1.1.1.1
!
spanning-tree mode rapid-pvst
spanning-tree portfast default
spanning-tree extend system-id
!
interface GigabitEthernet1/0/1
 description Uplink to Core Router (Active)
 no switchport
 ip address %s 255.255.255.252
 ip ospf 1 area 0
!
interface GigabitEthernet1/0/2
 description Trunk Link to Dist-Switch-1 (LACP member)
 switchport trunk encapsulation dot1q
 switchport mode trunk
 channel-group 1 mode active
!
interface GigabitEthernet1/0/3
 description Trunk Link to Dist-Switch-2 (LACP member)
 switchport trunk encapsulation dot1q
 switchport mode trunk
 channel-group 1 mode active
!
interface GigabitEthernet1/0/4
 description Link to Server_Rack_01 (ESXi Host)
 switchport trunk encapsulation dot1q
 switchport mode trunk
!
interface GigabitEthernet1/0/5
 description %s
 switchport access vlan %d
 switchport mode access
 spanning-tree portfast%s
!
interface GigabitEthernet1/0/6
 description VoIP Desk Phone
 switchport access vlan %d
 switchport voice vlan %d
 spanning-tree portfast
!%s
interface Vlan%d
 description Out-of-band Management Interface
 ip address 10.254.%d.1 255.255.255.0
 ip helper-address 10.100.1.5
!
interface Vlan%d
 description Gateway for User Data
 ip address 10.%d.1.1 255.255.255.0
 ip helper-address 10.100.1.5
!
router ospf 1
 router-id 10.254.1.1
 log-adjacency-changes
 passive-interface default
 no passive-interface GigabitEthernet1/0/1
 network 10.%d.1.0 0.0.0.255 area 0
 network 10.254.%d.0 0.0.0.255 area 0
!
ip route 0.0.0.0 0.0.0.0 10.254.1.2
!
ip access-list extended SECURE_MGMT
 permit tcp 10.254.%d.0 0.0.0.255 any eq 22
 permit icmp any any echo
 deny ip any any log
!
logging %s
logging trap informational
snmp-server community public RO
snmp-server contact Network_Operations_Center
!
line con 0
 exec-timeout 5 0
 stopbits 1
line vty 0 4
 access-class SECURE_MGMT in
 exec-timeout 15 0
 login local
 transport input ssh
!
end`, 
		configChangeLog,
		cleanName, 
		vlanId, idSuffix, 
		vlanId+10, idSuffix, 
		vlanId+20, idSuffix, 
		vlan100Name,
		dev.IP, 
		gig5Desc,
		vlanId,
		gig5Shutdown,
		vlanId+10, 
		vlanId+20, 
		loopback0,
		vlanId, ipSuffix, 
		vlanId+10, ipSuffix, 
		ipSuffix, vlanId, 
		vlanId,
		syslogIP,
	)), nil
}
