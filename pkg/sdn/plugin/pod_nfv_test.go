package plugin

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/openshift/origin/pkg/sdn/plugin/cniserver"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kapi "k8s.io/kubernetes/pkg/api"
	kexec "k8s.io/kubernetes/pkg/util/exec"

	"github.com/containernetworking/cni/pkg/ns"
	cnitypes "github.com/containernetworking/cni/pkg/types"

	"github.com/vishvananda/netlink"

	"github.com/d2g/dhcp4"
	"github.com/d2g/dhcp4server"
	"github.com/d2g/dhcp4server/leasepool"
	"github.com/d2g/dhcp4server/leasepool/memorypool"
)

type linkDesc struct {
	name     string
	linkType string
	ip       string
	vlanid   uint

	// If the link isn't in the current pod
	podNamespace string
	podName      string
}

func newLinkDesc(name, linkType, ip string) linkDesc {
	return linkDesc{
		name:     name,
		linkType: linkType,
		ip:       ip,
	}
}

func newVlanLinkDesc(name, ip string, vlanid uint) linkDesc {
	return linkDesc{
		name:     name,
		linkType: "vlan",
		ip:       ip,
		vlanid:   vlanid,
	}
}

func newVethLinkDesc(name, ip, podNamespace, podName string) linkDesc {
	return linkDesc{
		name:         name,
		linkType:     "veth",
		ip:           ip,
		podNamespace: podNamespace,
		podName:      podName,
	}
}

type opSetupFn func(t *testing.T, m *NfvManager, origNS, testNS ns.NetNS, stopCh <-chan bool) error

type vethLink struct {
	name string
	ip   string
	mac  string
}

type createVethDesc struct {
	main vethLink
	peer vethLink
}

type nfvOperation struct {
	skip        bool
	command     cniserver.CNICommand
	namespace   string
	name        string
	pod         *kapi.Pod
	expectSDN   bool
	expectNS    bool
	createLinks []string
	createVeth  *createVethDesc
	podLinks    []linkDesc
	setupFn     opSetupFn
	failStr     string // error string for failing the operation
	result      *cnitypes.Result
}

func nsKey(namespace, name string) string {
	return fmt.Sprintf("%s/%s", namespace, name)
}

func findAddr(l netlink.Link, expectedAddr string) error {
	if expectedAddr == "" {
		return nil
	}

	ip, ipn, err := net.ParseCIDR(expectedAddr)
	if err != nil {
		return fmt.Errorf("failed to parse test address %q", expectedAddr)
	}
	if ip.To4() != nil {
		ip = ip.To4()
	}
	eo, eb := ipn.Mask.Size()

	addrs, err := netlink.AddrList(l, syscall.AF_UNSPEC)
	if err != nil {
		return fmt.Errorf("failed to get interface %q addresses", l.Attrs().Name)
	}
	for _, addr := range addrs {
		if addr.IP.To4() != nil {
			addr.IP = addr.IP.To4()
		}
		if ip.Equal(addr.IP) {
			bo, bb := addr.Mask.Size()
			if eo == bo && eb == bb {
				// success
				return nil
			}
		}
	}
	return fmt.Errorf("failed to find address %q on container link %q", expectedAddr, l.Attrs().Name)
}

func validateLink(links []netlink.Link, expected linkDesc) error {
	for _, l := range links {
		if l.Attrs().Name != expected.name {
			continue
		}
		if l.Type() != expected.linkType {
			return fmt.Errorf("pod link %q type %q wasn't expected %q", expected.name, l.Type(), expected.linkType)
		}
		switch l.Type() {
		case "vlan":
			vl, ok := l.(*netlink.Vlan)
			if !ok {
				return fmt.Errorf("failed to cast link %q to VLAN", expected.name)
			}
			if vl.VlanId != int(expected.vlanid) {
				return fmt.Errorf("pod link %q VlanId %d wasn't expected %d", expected.name, vl.VlanId, expected.vlanid)
			}
		case "veth":
			if _, ok := l.(*netlink.Veth); !ok {
				return fmt.Errorf("failed to cast link %q to veth", expected.name)
			}
		}
		if err := findAddr(l, expected.ip); err != nil {
			return err
		}
		/* success */
		return nil
	}
	return fmt.Errorf("didn't find expected pod link %q", expected.name)
}

func mustParseCIDR(cidr string) net.IPNet {
	ip, net, err := net.ParseCIDR(cidr)
	if err != nil {
		panic("bad CIDR string constant " + cidr)
	}
	net.IP = ip
	if net.IP.To4() != nil {
		net.IP = net.IP.To4()
	}
	return *net
}

func dhcpSetup(t *testing.T, m *NfvManager, origNS, testNS ns.NetNS, stopCh <-chan bool) error {
	// Add the expected IP to the pool
	lp := memorypool.MemoryPool{}
	err := lp.AddLease(leasepool.Lease{IP: dhcp4.IPAdd(net.IPv4(192, 168, 1, 5), 0)})
	if err != nil {
		return fmt.Errorf("error adding IP to DHCP pool: %v", err)
	}

	dhcpServer, err := dhcp4server.New(
		net.IPv4(192, 168, 1, 1),
		&lp,
		dhcp4server.SetLocalAddr(net.UDPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 67}),
		dhcp4server.SetRemoteAddr(net.UDPAddr{IP: net.IPv4bcast, Port: 68}),
	)
	if err != nil {
		return fmt.Errorf("failed to create DHCP server: %v", err)
	}

	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		if err := origNS.Do(func(ns.NetNS) error {
			wg.Done()
			return dhcpServer.ListenAndServe()
		}); err != nil {
			t.Fatalf("Error running DHCP server: %v", err)
		}
	}()

	go func() {
		wg.Done()
		// Stop DHCP server in another goroutine so we don't block main one
		<-stopCh
		dhcpServer.Shutdown()
		m.KillDhcpClient()
	}()
	wg.Wait()

	return nil
}

const SlaacRALinkName string = "slaac-ra"

func checksum(b []byte) uint16 {
	csumcv := len(b) - 1 // checksum coverage
	s := uint32(0)
	for i := 0; i < csumcv; i += 2 {
		s += uint32(b[i+1])<<8 | uint32(b[i])
	}
	if csumcv&1 == 0 {
		s += uint32(b[csumcv])
	}
	s = s>>16 + s&0xffff
	s = s + s>>16
	return ^uint16(s)
}

func slaacSetup(t *testing.T, m *NfvManager, origNS, testNS ns.NetNS, stopCh <-chan bool) error {
	// Get the "router" link in the original netns
	var srcIP *net.IP
	var srcMAC *net.HardwareAddr
	if err := origNS.Do(func(ns.NetNS) error {
		link, err := netlink.LinkByName(SlaacRALinkName)
		if err != nil {
			return fmt.Errorf("failed to find IPv6 RA link: %v", err)
		}
		srcMAC = &link.Attrs().HardwareAddr

		// Get IPv6LL address, making sure we wait until it has completed DAD,
		// otherwise we cannot send from it
	loop:
		for i := 0; i < 10; i++ {
			addrs, err := netlink.AddrList(link, syscall.AF_INET6)
			if err != nil {
				return fmt.Errorf("failed to read IPv6 addresses from RA link: %v", err)
			}
			for _, a := range addrs {
				if a.IP.IsLinkLocalUnicast() && (a.Flags&syscall.IFA_F_TENTATIVE) == 0 {
					srcIP = &a.IP
					break loop
				}
			}
			time.Sleep(time.Second / 2)
		}
		if srcIP == nil {
			return fmt.Errorf("failed to retrieve non-tentative IPv6LL address")
		}

		return nil
	}); err != nil {
		return err
	}

	if srcIP == nil {
		return fmt.Errorf("failed to find IPv6 address from RA link")
	}
	if srcMAC == nil {
		return fmt.Errorf("failed to find IPv6 address from RA link")
	}

	// Header + source LL address option + prefix information option
	bytes := make([]byte, 16+8+32)

	// ICMPv6 header
	bytes[0] = 134                           // icmp6_type
	bytes[1] = 0                             // icmp6_code
	binary.BigEndian.PutUint16(bytes[2:], 0) // icmp6_cksum (zero when calculating)

	// RA fields
	bytes[4] = 0                                 // curhoplmit
	bytes[5] = 0                                 // flags_reserved
	binary.BigEndian.PutUint16(bytes[6:], 1800)  // nd_ra_router_lifetime
	binary.BigEndian.PutUint32(bytes[8:], 5000)  // nd_ra_reachable
	binary.BigEndian.PutUint32(bytes[12:], 1000) // nd_ra_retransmit

	// Options
	bytes[16] = 1 // Option Type - "source link layer address"
	bytes[17] = 1 // Option Len  - units of 8 octets
	copy(bytes[18:], *srcMAC)

	bytes[24] = 3                                 // Option Type - "prefix information"
	bytes[25] = 4                                 // Option Len  - units of 8 octets
	bytes[26] = 64                                // Prefix length
	bytes[27] = 0xC0                              // Flags - L and A bits set
	binary.BigEndian.PutUint32(bytes[28:], 86400) // prefix valid lifetime
	binary.BigEndian.PutUint32(bytes[32:], 14400) // prefix preferred lifetime
	prefix, _, err := net.ParseCIDR("2001:db8:1::/64")
	if err != nil {
		return fmt.Errorf("failed to parse prefix: %v", err)
	}
	copy(bytes[40:], prefix.To16())

	// pseudo-header for checksum calculations
	// Length = source IP (16 bytes) + destination IP (16 bytes)
	//   + upper layer packet length (4 bytes) + zero (3 bytes)
	//   + next header (1 byte) + ICMPv6 header (16 bytes)
	//   + ICMPv6 RA options (40 bytes)
	ph := make([]byte, 16+16+4+3+1+16+40)
	copy(ph, *srcIP)
	dstIP := net.ParseIP("ff02::1")
	copy(ph[16:], dstIP)
	ph[34] = (16 + 8) / 255 // Upper layer packet length
	ph[35] = (16 + 8) % 255 // Upper layer packet length
	ph[39] = syscall.IPPROTO_ICMPV6
	copy(ph[40:], bytes)

	// Checksum the pseudoheader and dump into actual header
	csum := checksum(ph)
	bytes[2] = byte(csum)
	bytes[3] = byte(csum >> 8)

	sa := &syscall.SockaddrInet6{}
	copy(sa.Addr[0:], dstIP)

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		if err := origNS.Do(func(ns.NetNS) error {
			// Open the socket
			data := make([]byte, 2)
			binary.BigEndian.PutUint16(data, syscall.IPPROTO_ICMPV6)
			pbe := binary.BigEndian.Uint16(data)
			sock, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, int(pbe))
			if err != nil {
				return fmt.Errorf("failed to open raw sock: %v", err)
			}
			defer syscall.Close(sock)
			if err := syscall.SetsockoptString(sock, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, SlaacRALinkName); err != nil {
				return fmt.Errorf("failed to bind to device: %v", err)
			}
			if err := syscall.SetsockoptInt(sock, syscall.IPPROTO_IPV6, syscall.IPV6_MULTICAST_HOPS, 255); err != nil {
				return fmt.Errorf("failed to set MC hops: %v", err)
			}

			wg.Done()
			for {
				// Send an RA every 3 seconds until told to stop
				if err := syscall.Sendto(sock, bytes, 0, sa); err != nil {
					return fmt.Errorf("failed to send RA: %v", err)
				}
				select {
				case <-time.After(time.Second * 3):
					break
				case <-stopCh:
					return nil
				}
			}
		}); err != nil {
			t.Fatalf("Error sending router advertisements: %v", err)
		}
	}()
	wg.Wait()

	return nil
}

func TestPodNFV(t *testing.T) {
	if os.Geteuid() != 0 {
		// reexec ourselves with sudo
		output, err := kexec.New().Command("sudo", "-E", "bash", "-c", "umask 0; go test -test.v github.com/openshift/origin/pkg/sdn/plugin").CombinedOutput()
		if err != nil {
			t.Fatalf("failed to re-exec test error '%v':\n%s", err, string(output))
		} else {
			t.Logf(string(output))
		}
		return
	}

	testcases := map[string]struct {
		operations []*nfvOperation
	}{
		"ADD+DEL": {
			operations: []*nfvOperation{
				{
					command:   cniserver.CNI_ADD,
					namespace: "namespace1",
					name:      "pod1",
					expectNS:  true,
					expectSDN: true,
					pod: &kapi.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Annotations: map[string]string{
								"pod.network.openshift.io/nfv-select-sdn": "true",
							},
						},
					},
				},
				{
					command:   cniserver.CNI_DEL,
					namespace: "namespace1",
					name:      "pod1",
					expectNS:  true,
					expectSDN: true,
				},
			},
		},
		"ADD+DEL two NICs": {
			operations: []*nfvOperation{
				{
					command:     cniserver.CNI_ADD,
					namespace:   "namespace1",
					name:        "pod2",
					expectNS:    true,
					createLinks: []string{"dummy0", "dummy1"},
					pod: &kapi.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Annotations: map[string]string{
								"pod.network.openshift.io/nfv-select-sdn": "false",
								"pod.network.openshift.io/nfv-networks": `{
  "customer": {
    "addressing": {
      "ips": [
        {"ip": "192.168.1.5/24","gateway": "192.168.1.1"}
      ],
      "routes": [
        {"dest": "10.5.6.0/24","nextHop": "192.168.1.2"},
        {"dest": "172.16.0.0/16","nextHop": "192.168.1.3"}
      ]
    },
    "interface": {
      "type": "vlan",
      "vlanId": 42,
      "ifname": "dummy0",
      "containerName": "eth1"
    }
  },
  "physdev": {
    "addressing": {
      "ips": [
        {"ip": "192.168.1.10/24","gateway": "192.168.1.1"}
      ]
    },
    "interface": {
      "type": "physical",
      "ifname": "dummy1",
      "containerName": "eth2"
    }
  }
}`,
							},
						},
					},
					podLinks: []linkDesc{
						newVlanLinkDesc("eth1", "192.168.1.5/24", 42),
						newLinkDesc("eth2", "dummy", "192.168.1.10/24"),
					},
					result: &cnitypes.Result{
						IP4: &cnitypes.IPConfig{
							IP:      mustParseCIDR("192.168.1.5/24"),
							Gateway: net.ParseIP("192.168.1.1").To4(),
							Routes: []cnitypes.Route{
								{
									Dst: mustParseCIDR("10.5.6.0/24"),
									GW:  net.ParseIP("192.168.1.2").To4(),
								},
								{
									Dst: mustParseCIDR("172.16.0.0/16"),
									GW:  net.ParseIP("192.168.1.3").To4(),
								},
							},
						},
					},
				},
				{
					command:   cniserver.CNI_DEL,
					namespace: "namespace1",
					name:      "pod2",
					expectNS:  true,
				},
			},
		},
		"ADD+DEL IPv6": {
			operations: []*nfvOperation{
				{
					command:     cniserver.CNI_ADD,
					namespace:   "namespace1",
					name:        "pod3",
					expectNS:    true,
					createLinks: []string{"dummy2"},
					pod: &kapi.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Annotations: map[string]string{
								"pod.network.openshift.io/nfv-select-sdn": "false",
								"pod.network.openshift.io/nfv-networks": `{
  "physdev": {
    "addressing": {
      "ips": [
        {"ip": "abcd:1234:ffff::cdde/64","gateway": "abcd:1234:ffff::cdd1"}
      ],
      "routes": [
        {"dest": "abbe:cafe::/64","nextHop": "abcd:1234:ffff::cdd2"},
        {"dest": "aaaa:cccc::/64","nextHop": "abcd:1234:ffff::cdd3"}
      ]
    },
    "interface": {
      "type": "physical",
      "ifname": "dummy2",
      "containerName": "eth1"
    }
  }
}`,
							},
						},
					},
					podLinks: []linkDesc{
						newLinkDesc("eth1", "dummy", "abcd:1234:ffff::cdde/64"),
					},
					result: &cnitypes.Result{
						IP6: &cnitypes.IPConfig{
							IP:      mustParseCIDR("abcd:1234:ffff::cdde/64"),
							Gateway: net.ParseIP("abcd:1234:ffff::cdd1"),
							Routes: []cnitypes.Route{
								{
									Dst: mustParseCIDR("abbe:cafe::/64"),
									GW:  net.ParseIP("abcd:1234:ffff::cdd2"),
								},
								{
									Dst: mustParseCIDR("aaaa:cccc::/64"),
									GW:  net.ParseIP("abcd:1234:ffff::cdd3"),
								},
							},
						},
					},
				},
				{
					command:   cniserver.CNI_DEL,
					namespace: "namespace1",
					name:      "pod3",
					expectNS:  true,
				},
			},
		},
		"SFC link1": {
			operations: []*nfvOperation{
				{
					command:   cniserver.CNI_ADD,
					namespace: "namespace2",
					name:      "vrtr",
					expectNS:  true,
					pod: &kapi.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Annotations: map[string]string{
								"pod.network.openshift.io/nfv-select-sdn": "false",
								"pod.network.openshift.io/nfv-service-function-chains": `[{
  "name": "foobar",
  "toPod": {
    "app": "vfirewall"
  },
  "localContainerName": "vfw-link",
  "localAddressing": {
    "ips": [
      {"ip":"1.2.3.4/24"}
    ]
  },
  "remoteContainerName": "vrtr-link",
  "remoteAddressing": {
    "ips": [
      {"ip":"1.2.3.3/24"}
    ]
  }
}]`,
							},
						},
					},
				},
				{
					command:   cniserver.CNI_ADD,
					namespace: "namespace2",
					name:      "vfw",
					expectNS:  true,
					pod: &kapi.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Labels: map[string]string{
								"app": "vfirewall",
							},
							Annotations: map[string]string{
								"pod.network.openshift.io/nfv-select-sdn": "false",
							},
						},
					},
					podLinks: []linkDesc{
						newVethLinkDesc("vfw-link", "1.2.3.4/24", "namespace2", "vrtr"),
						newVethLinkDesc("vrtr-link", "1.2.3.3/24", "namespace2", "vfw"),
					},
				},
				{
					command:   cniserver.CNI_DEL,
					namespace: "namespace2",
					name:      "vrtr",
					expectNS:  true,
				},
				{
					command:   cniserver.CNI_DEL,
					namespace: "namespace2",
					name:      "vfw",
					expectNS:  true,
				},
			},
		},
		// test that creating the pod with the SFC spec second also works
		"SFC link2": {
			operations: []*nfvOperation{
				{
					command:   cniserver.CNI_ADD,
					namespace: "namespace3",
					name:      "vfw",
					expectNS:  true,
					pod: &kapi.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Labels: map[string]string{
								"app": "vfirewall2",
							},
							Annotations: map[string]string{
								"pod.network.openshift.io/nfv-select-sdn": "false",
							},
						},
					},
				},
				{
					command:   cniserver.CNI_ADD,
					namespace: "namespace3",
					name:      "vrtr",
					expectNS:  true,
					pod: &kapi.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Annotations: map[string]string{
								"pod.network.openshift.io/nfv-select-sdn": "false",
								"pod.network.openshift.io/nfv-service-function-chains": `[{
  "name": "foobar",
  "toPod": {
    "app": "vfirewall2"
  },
  "localContainerName": "vfw-link",
  "localAddressing": {
    "ips": [
      {"ip":"1.2.3.4/24"}
    ]
  },
  "remoteContainerName": "vrtr-link",
  "remoteAddressing": {
    "ips": [
      {"ip":"1.2.3.3/24"}
    ]
  }
}]`,
							},
						},
					},
					podLinks: []linkDesc{
						newVethLinkDesc("vfw-link", "1.2.3.4/24", "namespace3", "vrtr"),
						newVethLinkDesc("vrtr-link", "1.2.3.3/24", "namespace3", "vfw"),
					},
				},
				{
					command:   cniserver.CNI_DEL,
					namespace: "namespace3",
					name:      "vrtr",
					expectNS:  true,
				},
				{
					command:   cniserver.CNI_DEL,
					namespace: "namespace3",
					name:      "vfw",
					expectNS:  true,
				},
			},
		},
		"SFC IPv6": {
			operations: []*nfvOperation{
				{
					command:   cniserver.CNI_ADD,
					namespace: "namespace4",
					name:      "vrtr",
					expectNS:  true,
					pod: &kapi.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Annotations: map[string]string{
								"pod.network.openshift.io/nfv-select-sdn": "false",
								"pod.network.openshift.io/nfv-service-function-chains": `[{
  "name": "foobar",
  "toPod": {
    "app": "vfirewall3"
  },
  "localContainerName": "vfw-link",
  "localAddressing": {
    "ips": [
      {"ip":"abcd:1234:ffff::1/128"}
    ]
  },
  "remoteContainerName": "vrtr-link",
  "remoteAddressing": {
    "ips": [
      {"ip":"abcd:1234:ffff::2/128"}
    ]
  }
}]`,
							},
						},
					},
				},
				{
					command:   cniserver.CNI_ADD,
					namespace: "namespace4",
					name:      "vfw",
					expectNS:  true,
					pod: &kapi.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Labels: map[string]string{
								"app": "vfirewall3",
							},
							Annotations: map[string]string{
								"pod.network.openshift.io/nfv-select-sdn": "false",
							},
						},
					},
					podLinks: []linkDesc{
						newVethLinkDesc("vfw-link", "abcd:1234:ffff::1/128", "namespace4", "vrtr"),
						newVethLinkDesc("vrtr-link", "abcd:1234:ffff::2/128", "namespace4", "vfw"),
					},
				},
				{
					command:   cniserver.CNI_DEL,
					namespace: "namespace4",
					name:      "vrtr",
					expectNS:  true,
				},
				{
					command:   cniserver.CNI_DEL,
					namespace: "namespace4",
					name:      "vfw",
					expectNS:  true,
				},
			},
		},
		"ADD+DEL SRIOV": {
			operations: []*nfvOperation{
				{
					// SKIP SRIOV since most systems won't have it
					skip:      true,
					command:   cniserver.CNI_ADD,
					namespace: "namespace5",
					name:      "pod1",
					expectNS:  true,
					pod: &kapi.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Annotations: map[string]string{
								"pod.network.openshift.io/nfv-select-sdn": "false",
								"pod.network.openshift.io/nfv-networks": `{
  "customer": {
    "addressing": {
      "type": "static",
      "ips": [
        {"ip": "192.168.1.5/24","gateway": "192.168.1.1"}
      ]
    },
    "interface": {
      "type": "sriov",
      "vfIndex": 1,
      "vfVlan": 1234,
      "ifname": "em2",
      "containerName": "eth1"
    }
  }
}`,
							},
						},
					},
					podLinks: []linkDesc{
						newLinkDesc("eth1", "device", "192.168.1.5/24"),
					},
					result: &cnitypes.Result{
						IP4: &cnitypes.IPConfig{
							IP:      mustParseCIDR("192.168.1.5/24"),
							Gateway: net.ParseIP("192.168.1.1").To4(),
						},
					},
				},
				{
					// SKIP SRIOV since most systems won't have it
					skip:      true,
					command:   cniserver.CNI_DEL,
					namespace: "namespace5",
					name:      "pod1",
					expectNS:  true,
				},
			},
		},
		"ADD+DEL DHCP": {
			operations: []*nfvOperation{
				{
					command:   cniserver.CNI_ADD,
					namespace: "namespace-dhcp",
					name:      "pod1",
					expectNS:  true,
					createVeth: &createVethDesc{
						main: vethLink{
							name: "dhcp-server",
							ip:   "192.168.1.1/24",
						},
						peer: vethLink{
							name: "dhcp-client",
						},
					},
					setupFn: dhcpSetup,
					pod: &kapi.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Annotations: map[string]string{
								"pod.network.openshift.io/nfv-select-sdn": "false",
								"pod.network.openshift.io/nfv-networks": `{
  "customer": {
    "addressing": {
      "dhcp4": true
    },
    "interface": {
      "type": "physical",
      "ifname": "dhcp-client",
      "containerName": "eth1"
    }
  }
}`,
							},
						},
					},
					podLinks: []linkDesc{
						newVethLinkDesc("eth1", "192.168.1.5/24", "", ""),
					},
					result: &cnitypes.Result{
						IP4: &cnitypes.IPConfig{
							IP:      mustParseCIDR("192.168.1.5/24"),
							Gateway: net.ParseIP("192.168.1.1").To4(),
						},
					},
				},
				{
					command:   cniserver.CNI_DEL,
					namespace: "namespace-dhcp",
					name:      "pod1",
					expectNS:  true,
				},
			},
		},
		"ADD+DEL IPv6 SLAAC": {
			operations: []*nfvOperation{
				{
					command:   cniserver.CNI_ADD,
					namespace: "namespace-slaac",
					name:      "pod1",
					expectNS:  true,
					createVeth: &createVethDesc{
						main: vethLink{
							name: "slaac-ra",
							mac:  "52:44:55:66:77:88",
						},
						peer: vethLink{
							name: "slaac-client",
							mac:  "52:22:33:44:55:66",
						},
					},
					setupFn: slaacSetup,
					pod: &kapi.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Annotations: map[string]string{
								"pod.network.openshift.io/nfv-select-sdn": "false",
								"pod.network.openshift.io/nfv-networks": `{
  "customer": {
    "addressing": {
      "slaac6": true
    },
    "interface": {
      "type": "physical",
      "ifname": "slaac-client",
      "containerName": "eth1"
    }
  }
}`,
							},
						},
					},
					podLinks: []linkDesc{
						newVethLinkDesc("eth1", "2001:db8:1::5022:33ff:fe44:5566/64", "", ""),
					},
					result: &cnitypes.Result{
						IP6: &cnitypes.IPConfig{
							IP:      mustParseCIDR("2001:db8:1::5022:33ff:fe44:5566/64"),
							Gateway: net.ParseIP("fe80::5044:55ff:fe66:7788"),
						},
					},
				},
				{
					command:   cniserver.CNI_DEL,
					namespace: "namespace-slaac",
					name:      "pod1",
					expectNS:  true,
				},
			},
		},
	}

	testNSs := make(map[string]ns.NetNS)

	// Create a new NetNS so we don't modify the host
	originalNS, err := ns.NewNS()
	if err != nil {
		t.Fatalf("failed to create original test netns: %v", err)
	}
	testNSs[""] = originalNS

	// Close all open NetNS created by the test
	defer func(nss *map[string]ns.NetNS) {
		for _, ns := range *nss {
			ns.Close()
		}
	}(&testNSs)

	fexec := &kexec.FakeExec{}
	nfv := NewNfvManager(fexec, originalNS)

	for k, tc := range testcases {
		for opidx, op := range tc.operations {
			var testNS ns.NetNS
			var netnsPath string

			if op.skip {
				continue
			}

			if err := originalNS.Do(func(ns.NetNS) error {
				for _, ifname := range op.createLinks {
					if err := netlink.LinkAdd(&netlink.Dummy{
						LinkAttrs: netlink.LinkAttrs{
							Name: ifname,
						},
					}); err != nil {
						return fmt.Errorf("failed to add link %q: %v", ifname, err)
					}
					link, err := netlink.LinkByName(ifname)
					if err != nil {
						return err
					}
					if err := netlink.LinkSetUp(link); err != nil {
						return err
					}
				}

				if op.createVeth != nil {
					if err := netlink.LinkAdd(&netlink.Veth{
						LinkAttrs: netlink.LinkAttrs{
							Name: op.createVeth.main.name,
						},
						PeerName: op.createVeth.peer.name,
					}); err != nil {
						return fmt.Errorf("failed to add link %q: %v", op.createVeth.main.name, err)
					}
					for _, vl := range []vethLink{op.createVeth.main, op.createVeth.peer} {
						link, err := netlink.LinkByName(vl.name)
						if err != nil {
							return err
						}
						if err := netlink.LinkSetDown(link); err != nil {
							return err
						}
						if vl.mac != "" {
							mac, err := net.ParseMAC(vl.mac)
							if err != nil {
								return fmt.Errorf("failed to parse veth peer mac %q: %v", vl.mac, err)
							}
							if err := netlink.LinkSetHardwareAddr(link, mac); err != nil {
								return fmt.Errorf("failed to set veth peer mac %q: %v", vl.mac, err)
							}
						}
						if err := netlink.LinkSetUp(link); err != nil {
							return err
						}
						if vl.ip != "" {
							ip, ipn, _ := net.ParseCIDR(vl.ip)
							if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: ipn}); err != nil {
								return err
							}
							var dstIP net.IP
							if ip.To4() != nil {
								dstIP = net.IPv4zero
							} else {
								dstIP = net.IPv6zero
							}
							if err := netlink.RouteAdd(&netlink.Route{
								Scope:     netlink.SCOPE_UNIVERSE,
								LinkIndex: link.Attrs().Index,
								Dst:       &net.IPNet{IP: dstIP},
							}); err != nil {
								return err
							}
						}
					}
				}
				return nil
			}); err != nil {
				t.Fatalf("(%s/%d) failed to set up original test netns: %v", k, opidx, err)
			}

			nskey := nsKey(op.namespace, op.name)
			if op.expectNS {
				if op.command == cniserver.CNI_ADD {
					testNS, err = ns.NewNS()
					if err != nil {
						t.Fatalf("(%s/%d) failed to create test netns: %v", k, opidx, err)
					}
					testNSs[nskey] = testNS
				} else {
					var ok bool
					testNS, ok = testNSs[nskey]
					if !ok {
						t.Fatalf("(%s/%d) expected existing pod netns", k, opidx)
					}
				}
				netnsPath = testNS.Path()
			}

			request := &cniserver.PodRequest{
				Command:      op.command,
				PodNamespace: op.namespace,
				PodName:      op.name,
				ContainerId:  fmt.Sprintf("%s.%s", op.namespace, op.name),
				Netns:        netnsPath,
			}

			stopCh := make(chan bool)
			if op.setupFn != nil {
				if err := op.setupFn(t, nfv, originalNS, testNS, stopCh); err != nil {
					t.Fatalf("(%s/%d) failed to run setup function: %v", err)
				}
			}

			var wantSDN bool
			var result *cnitypes.Result
			err = originalNS.Do(func(ns.NetNS) error {
				switch op.command {
				case cniserver.CNI_ADD:
					wantSDN, result, err = nfv.nfvSetup(request, op.pod)
					if err == nil && !reflect.DeepEqual(result, op.result) {
						if result.IP6 != nil {
							return fmt.Errorf("setup got\n%#v\nexpected %#v", result.IP6, op.result.IP6)
						} else {
							return fmt.Errorf("setup got\n%#v\nexpected %#v", result.IP4, op.result.IP4)
						}
					}
				case cniserver.CNI_DEL:
					wantSDN, err = nfv.nfvTeardown(request, netnsPath != "")
				}
				return err
			})
			if op.setupFn != nil {
				stopCh <- true
			}
			if err != nil {
				t.Fatalf("(%s/%d) failed to run NFV operation in original NS: %v", k, opidx, err)
			}

			if op.failStr != "" {
				if err == nil {
					t.Fatalf("(%s/%d) expected failure %q", k, opidx, op.failStr)
				} else if !strings.HasPrefix(err.Error(), op.failStr) {
					t.Fatalf("(%s/%d) expected failure %q; got %q", k, opidx, op.failStr, err.Error())
				}
			} else if err != nil {
				t.Fatalf("(%s/%d) unexpected failure %q", k, opidx, err.Error())
			}

			if wantSDN != op.expectSDN {
				t.Fatalf("(%s/%d) expected SDN %v doesn't match returned %v", k, opidx, op.expectSDN, wantSDN)
			}

			switch op.command {
			case cniserver.CNI_ADD:
				for _, el := range op.podLinks {
					netns := testNS
					if el.podNamespace != "" {
						var ok bool
						nskey := nsKey(el.podNamespace, el.podName)
						netns, ok = testNSs[nskey]
						if !ok {
							t.Fatalf("failed to find netns %q", nskey)
						}
					}

					if err := netns.Do(func(ns.NetNS) error {
						links, err := netlink.LinkList()
						if err != nil {
							return err
						}
						if err := validateLink(links, el); err != nil {
							return err
						}
						return nil
					}); err != nil {
						t.Fatalf("(%s/%d) %v", k, opidx, err)
					}
				}
			}
		}
	}
}
