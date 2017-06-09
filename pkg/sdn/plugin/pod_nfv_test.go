package plugin

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"reflect"
	"runtime"
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
	cnicurrent "github.com/containernetworking/cni/pkg/types/current"

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

func newBridgeLinkDesc(name string, vlanid uint) linkDesc {
	return linkDesc{
		name:     name,
		linkType: "bridge",
		vlanid:   vlanid,
	}
}

type opSetupFn func(m *NfvManager, origNS ns.NetNS, stopCh <-chan bool) error

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
	command       cniserver.CNICommand
	namespace     string
	name          string
	pod           *kapi.Pod
	expectSDN     bool
	createDummys  []string
	createVeth    *createVethDesc
	expectedLinks []linkDesc
	setupFn       opSetupFn
	failStr       string // error string for failing the operation
	result        *cnicurrent.Result
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

func mustParseIPNet(cidr string) net.IPNet {
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

func mustParseIP(addr string) net.IP {
	ip := net.ParseIP(addr)
	if ip == nil {
		panic("bad IP string constant " + addr)
	}
	if ip.To4() != nil {
		ip = ip.To4()
	}
	return ip
}

func dhcpSetup(m *NfvManager, origNS ns.NetNS, stopCh <-chan bool) error {
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
			fmt.Printf("Error running DHCP server: %v\n", err)
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

func slaacSetup(m *NfvManager, origNS ns.NetNS, stopCh <-chan bool) error {
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
			fmt.Printf("Error sending router advertisements: %v\n", err)
		}
	}()
	wg.Wait()

	return nil
}

func createVeths(veths *createVethDesc) error {
	if veths == nil {
		return nil
	}

	if err := netlink.LinkAdd(&netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: veths.main.name,
		},
		PeerName: veths.peer.name,
	}); err != nil {
		return fmt.Errorf("failed to add link %q: %v", veths.main.name, err)
	}
	for _, vl := range []vethLink{veths.main, veths.peer} {
		link, err := netlink.LinkByName(vl.name)
		if err != nil {
			return fmt.Errorf("failed to retrieve veth link %q: %v", vl.name, err)
		}
		if err := netlink.LinkSetDown(link); err != nil {
			return fmt.Errorf("failed to set veth link %q down: %v", vl.name, err)
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
			return fmt.Errorf("failed to set veth link %q up: %v", vl.name, err)
		}
		if vl.ip != "" {
			ip, ipn, _ := net.ParseCIDR(vl.ip)
			if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: ipn}); err != nil {
				return fmt.Errorf("failed to add address %q to veth link %q: %v", vl.ip, vl.name, err)
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
				return fmt.Errorf("failed to add default route through veth link %q: %v", vl.name, err)
			}
		}
	}

	return nil
}

func createDummys(links []string) error {
	for _, ifname := range links {
		if err := netlink.LinkAdd(&netlink.Dummy{
			LinkAttrs: netlink.LinkAttrs{
				Name: ifname,
			},
		}); err != nil {
			return fmt.Errorf("failed to add link %q: %v", ifname, err)
		}
		link, err := netlink.LinkByName(ifname)
		if err != nil {
			return fmt.Errorf("failed to retrieve dummy link %q: %v", ifname, err)
		}
		if err := netlink.LinkSetUp(link); err != nil {
			return fmt.Errorf("failed to set dummy link %q up: %v", ifname, err)
		}
	}
	return nil
}

func validateExpectedLinks(expectedLinks []linkDesc, nsm *nsManager, testNS, originalNS ns.NetNS) error {
	for _, el := range expectedLinks {
		var err error

		// Might want to validate another pod's link (eg, SFC)
		netns := testNS
		if el.podNamespace != "" {
			netns, err = nsm.ensureNS(el.podNamespace, el.podName, false)
			if err != nil {
				return err
			}
		} else if el.linkType == "bridge" {
			netns = originalNS
		}

		if err := netns.Do(func(ns.NetNS) error {
			link, err := netlink.LinkByName(el.name)
			if err != nil {
				return fmt.Errorf("failed to find expected pod %s/%s link %q: %v", el.podNamespace, el.podName, el.name, err)
			}
			if link.Type() != el.linkType {
				return fmt.Errorf("pod link %q type %q wasn't expected %q", el.name, link.Type(), el.linkType)
			}
			switch link.Type() {
			case "vlan":
				vl, ok := link.(*netlink.Vlan)
				if !ok {
					return fmt.Errorf("failed to cast link %q to VLAN", el.name)
				}
				if vl.VlanId != int(el.vlanid) {
					return fmt.Errorf("pod link %q VlanId %d wasn't expected %d", el.name, vl.VlanId, el.vlanid)
				}
			case "veth":
				if _, ok := link.(*netlink.Veth); !ok {
					return fmt.Errorf("failed to cast link %q to veth", el.name)
				}
			case "bridge":
				if _, ok := link.(*netlink.Bridge); !ok {
					return fmt.Errorf("failed to cast link %q to bridge", el.name)
				}
				// Find a bridge port that's a VLAN of the given ID
				links, err := netlink.LinkList()
				if err != nil {
					return fmt.Errorf("failed to list links: %v", err)
				}
				found := false
				for _, l := range links {
					if l.Attrs().MasterIndex != link.Attrs().Index {
						continue
					}
					vlport, ok := l.(*netlink.Vlan)
					if !ok {
						continue
					}
					if vlport.VlanId != int(el.vlanid) {
						return fmt.Errorf("bridge %q vlan port %q had unexpected VLAN ID %d (expected %d)", el.name, l.Attrs().Name, vlport.VlanId, el.vlanid)
					}
					found = true
					break
				}
				if !found {
					return fmt.Errorf("failed to find port with VLAN ID %d on bridge %q %s", el.vlanid, el.name)
				}
			}
			return findAddr(link, el.ip)
		}); err != nil {
			return err
		}
	}
	return nil
}

type nsManager struct {
	originalNS ns.NetNS
	otherNS    map[string]ns.NetNS
}

func newNsManager() (*nsManager, ns.NetNS, error) {
	// Create a new NetNS so we don't modify the host
	originalNS, err := ns.NewNS()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create original test netns: %v", err)
	}

	return &nsManager{
		originalNS: originalNS,
		otherNS:    make(map[string]ns.NetNS),
	}, originalNS, nil
}

func (nsm *nsManager) ensureNS(namespace, name string, create bool) (ns.NetNS, error) {
	var netns ns.NetNS
	var err error

	nskey := fmt.Sprintf("%s/%s", namespace, name)
	if create {
		netns, err = ns.NewNS()
		if err != nil {
			return nil, fmt.Errorf("failed to create test netns %s: %v", nskey, err)
		}
		nsm.otherNS[nskey] = netns
	} else {
		var ok bool
		netns, ok = nsm.otherNS[nskey]
		if !ok {
			return nil, fmt.Errorf("test netns %s expected but not found", nskey)
		}
	}
	return netns, nil
}

func (nsm *nsManager) cleanup() {
	nsm.originalNS.Close()
	for _, ns := range nsm.otherNS {
		ns.Close()
	}
}

func runTestAsRoot(t *testing.T) bool {
	// Nothing to do if we're already root
	if os.Geteuid() == 0 {
		return true
	}

	const testPath string = "github.com/openshift/origin/pkg/sdn/plugin"

	// Grab the parent function name
	pc := make([]uintptr, 10)
	runtime.Callers(2, pc)
	f := runtime.FuncForPC(pc[0])
	testName := strings.TrimPrefix(f.Name(), fmt.Sprintf("%s.Test", testPath))

	// reexec ourselves with sudo
	sudoCmd := fmt.Sprintf("umask 0; go test -test.v -run %s %s", testName, testPath)
	output, err := kexec.New().Command("sudo", "-E", "bash", "-c", sudoCmd).CombinedOutput()
	if err != nil {
		t.Fatalf("failed to re-exec test error '%v':\n%s", err, string(output))
	} else {
		t.Logf(string(output))
	}
	return false
}

func runTestCommon(t *testing.T, ops []*nfvOperation) {
	nsm, originalNS, err := newNsManager()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer nsm.cleanup()

	fexec := &kexec.FakeExec{}
	nfv := NewNfvManager(fexec)

	for _, op := range ops {
		if err := originalNS.Do(func(ns.NetNS) error {
			if err := createDummys(op.createDummys); err != nil {
				return err
			}
			if err := createVeths(op.createVeth); err != nil {
				return err
			}
			return nil
		}); err != nil {
			t.Fatalf("failed to set up original test netns: %v", err)
		}

		create := op.command == cniserver.CNI_ADD
		testNS, err := nsm.ensureNS(op.namespace, op.name, create)
		if err != nil {
			t.Fatalf(err.Error())
		}
		netnsPath := testNS.Path()

		request := &cniserver.PodRequest{
			Command:      op.command,
			PodNamespace: op.namespace,
			PodName:      op.name,
			SandboxID:    fmt.Sprintf("%s.%s", op.namespace, op.name),
			Netns:        netnsPath,
		}

		var wantSDN bool
		var r cnitypes.Result
		err = originalNS.Do(func(ns.NetNS) error {
			switch op.command {
			case cniserver.CNI_ADD:
				stopCh := make(chan bool)
				if op.setupFn != nil {
					if err := op.setupFn(nfv, originalNS, stopCh); err != nil {
						t.Fatalf("failed to run setup function: %v", err)
					}
				}

				wantSDN, r, err = nfv.nfvSetup(request, op.pod)

				if op.setupFn != nil {
					stopCh <- true
				}

				if err == nil {
					if r != nil {
						result, ok := r.(*cnicurrent.Result)
						if !ok {
							return fmt.Errorf("failed to convert result %+v to current", r)
						}
						// Remove interface details (can't pre-determine them in the expected result)
						for _, intf := range result.Interfaces {
							intf.Mac = ""
							intf.Sandbox = ""
						}
						if !reflect.DeepEqual(result, op.result) {
							return fmt.Errorf("\nsetup got\n  %+v\nexpected\n  %+v\n", *result, *op.result)
						}
						if err := validateExpectedLinks(op.expectedLinks, nsm, testNS, originalNS); err != nil {
							t.Fatalf(err.Error())
						}
					} else if op.result != nil {
						return fmt.Errorf("expected result %v but got nil", op.result)
					}
				}
			case cniserver.CNI_DEL:
				wantSDN, err = nfv.nfvTeardown(request, netnsPath != "")
			}
			return err
		})
		if err != nil {
			t.Fatalf("failed to run NFV operation in original NS: %v", err)
		}

		if op.failStr != "" {
			if err == nil {
				t.Fatalf("expected failure %q", op.failStr)
			} else if !strings.HasPrefix(err.Error(), op.failStr) {
				t.Fatalf("expected failure %q; got %v", op.failStr, err)
			}
		} else if err != nil {
			t.Fatalf("unexpected failure %v", err)
		}

		if wantSDN != op.expectSDN {
			t.Fatalf("expected SDN %v doesn't match returned %v", op.expectSDN, wantSDN)
		}
	}
}

func TestPodNFVUseSDN(t *testing.T) {
	if !runTestAsRoot(t) {
		return
	}

	runTestCommon(t, []*nfvOperation{
		{
			command:   cniserver.CNI_ADD,
			namespace: "namespace1",
			name:      "pod1",
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
			expectSDN: true,
		},
	})
}

func TestPodNFVTwoNICs(t *testing.T) {
	if !runTestAsRoot(t) {
		return
	}

	runTestCommon(t, []*nfvOperation{
		{
			command:      cniserver.CNI_ADD,
			namespace:    "namespace1",
			name:         "pod2",
			createDummys: []string{"dummy0", "dummy1"},
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
			expectedLinks: []linkDesc{
				newVlanLinkDesc("eth1", "192.168.1.5/24", 42),
				newLinkDesc("eth2", "dummy", "192.168.1.10/24"),
			},
			result: &cnicurrent.Result{
				Interfaces: []*cnicurrent.Interface{
					{
						Name: "eth1",
					},
				},
				IPs: []*cnicurrent.IPConfig{
					{
						Version: "4",
						Address: mustParseIPNet("192.168.1.5/24"),
						Gateway: mustParseIP("192.168.1.1"),
					},
				},
				Routes:  []*cnitypes.Route{
					{
						Dst: mustParseIPNet("10.5.6.0/24"),
						GW: mustParseIP("192.168.1.2"),
					},
					{
						Dst: mustParseIPNet("172.16.0.0/16"),
						GW: mustParseIP("192.168.1.3"),
					},
				},
			},
		},
		{
			command:   cniserver.CNI_DEL,
			namespace: "namespace1",
			name:      "pod2",
		},
	})
}

func TestPodNFVIPv6(t *testing.T) {
	if !runTestAsRoot(t) {
		return
	}

	runTestCommon(t, []*nfvOperation{
		{
			command:      cniserver.CNI_ADD,
			namespace:    "namespace1",
			name:         "pod3",
			createDummys: []string{"dummy2"},
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
			expectedLinks: []linkDesc{
				newLinkDesc("eth1", "dummy", "abcd:1234:ffff::cdde/64"),
			},
			result: &cnicurrent.Result{
				Interfaces: []*cnicurrent.Interface{
					{
						Name: "eth1",
					},
				},
				IPs: []*cnicurrent.IPConfig{
					{
						Version: "6",
						Address: mustParseIPNet("abcd:1234:ffff::cdde/64"),
						Gateway: mustParseIP("abcd:1234:ffff::cdd1"),
					},
				},
				Routes: []*cnitypes.Route{
					{
						Dst: mustParseIPNet("abbe:cafe::/64"),
						GW:  mustParseIP("abcd:1234:ffff::cdd2"),
					},
					{
						Dst: mustParseIPNet("aaaa:cccc::/64"),
						GW:  mustParseIP("abcd:1234:ffff::cdd3"),
					},
				},
			},
		},
		{
			command:   cniserver.CNI_DEL,
			namespace: "namespace1",
			name:      "pod3",
		},
	})
}

func TestPodNFVSFCLink1(t *testing.T) {
	if !runTestAsRoot(t) {
		return
	}

	runTestCommon(t, []*nfvOperation{
		{
			command:   cniserver.CNI_ADD,
			namespace: "namespace2",
			name:      "vrtr",
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
			expectedLinks: []linkDesc{
				newVethLinkDesc("vfw-link", "1.2.3.4/24", "namespace2", "vrtr"),
				newVethLinkDesc("vrtr-link", "1.2.3.3/24", "namespace2", "vfw"),
			},
		},
		{
			command:   cniserver.CNI_DEL,
			namespace: "namespace2",
			name:      "vrtr",
		},
		{
			command:   cniserver.CNI_DEL,
			namespace: "namespace2",
			name:      "vfw",
		},
	})
}

func TestPodNFVSFCLink2(t *testing.T) {
	if !runTestAsRoot(t) {
		return
	}

	// test that creating the pod with the SFC spec second also works
	runTestCommon(t, []*nfvOperation{
		{
			command:   cniserver.CNI_ADD,
			namespace: "namespace3",
			name:      "vfw",
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
			expectedLinks: []linkDesc{
				newVethLinkDesc("vfw-link", "1.2.3.4/24", "namespace3", "vrtr"),
				newVethLinkDesc("vrtr-link", "1.2.3.3/24", "namespace3", "vfw"),
			},
		},
		{
			command:   cniserver.CNI_DEL,
			namespace: "namespace3",
			name:      "vrtr",
		},
		{
			command:   cniserver.CNI_DEL,
			namespace: "namespace3",
			name:      "vfw",
		},
	})
}

func TestPodNFVSFCIPv6(t *testing.T) {
	if !runTestAsRoot(t) {
		return
	}

	runTestCommon(t, []*nfvOperation{
		{
			command:   cniserver.CNI_ADD,
			namespace: "namespace4",
			name:      "vrtr",
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
			expectedLinks: []linkDesc{
				newVethLinkDesc("vfw-link", "abcd:1234:ffff::1/128", "namespace4", "vrtr"),
				newVethLinkDesc("vrtr-link", "abcd:1234:ffff::2/128", "namespace4", "vfw"),
			},
		},
		{
			command:   cniserver.CNI_DEL,
			namespace: "namespace4",
			name:      "vrtr",
		},
		{
			command:   cniserver.CNI_DEL,
			namespace: "namespace4",
			name:      "vfw",
		},
	})
}

func TestPodNFVSRIOV(t *testing.T) {
	if !runTestAsRoot(t) {
		return
	}

	// SKIP SRIOV since most systems won't have it
	return

	runTestCommon(t, []*nfvOperation{
		{
			command:   cniserver.CNI_ADD,
			namespace: "namespace5",
			name:      "pod1",
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
			expectedLinks: []linkDesc{
				newLinkDesc("eth1", "device", "192.168.1.5/24"),
			},
			result: &cnicurrent.Result{
				Interfaces: []*cnicurrent.Interface{
					{
						Name: "eth1",
					},
				},
				IPs: []*cnicurrent.IPConfig{
					{
						Version: "4",
						Address: mustParseIPNet("192.168.1.5/24"),
						Gateway: mustParseIP("192.168.1.1"),
					},
				},
			},
		},
		{
			command:   cniserver.CNI_DEL,
			namespace: "namespace5",
			name:      "pod1",
		},
	})
}

func TestPodNFVDHCP(t *testing.T) {
	if !runTestAsRoot(t) {
		return
	}

	runTestCommon(t, []*nfvOperation{
		{
			command:   cniserver.CNI_ADD,
			namespace: "namespace-dhcp",
			name:      "pod1",
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
			expectedLinks: []linkDesc{
				newVethLinkDesc("eth1", "192.168.1.5/24", "", ""),
			},
			result: &cnicurrent.Result{
				Interfaces: []*cnicurrent.Interface{
					{
						Name: "eth1",
					},
				},
				IPs: []*cnicurrent.IPConfig{
					{
						Version: "4",
						Address: mustParseIPNet("192.168.1.5/24"),
						Gateway: mustParseIP("192.168.1.1"),
					},
				},
			},
		},
		{
			command:   cniserver.CNI_DEL,
			namespace: "namespace-dhcp",
			name:      "pod1",
		},
	})
}

func TestPodNFVIPv6SLAAC(t *testing.T) {
	if !runTestAsRoot(t) {
		return
	}

	runTestCommon(t, []*nfvOperation{
		{
			command:   cniserver.CNI_ADD,
			namespace: "namespace-slaac",
			name:      "pod1",
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
			expectedLinks: []linkDesc{
				newVethLinkDesc("eth1", "2001:db8:1::5022:33ff:fe44:5566/64", "", ""),
			},
			result: &cnicurrent.Result{
				Interfaces: []*cnicurrent.Interface{
					{
						Name: "eth1",
					},
				},
				IPs: []*cnicurrent.IPConfig{
					{
						Version: "6",
						Address: mustParseIPNet("2001:db8:1::5022:33ff:fe44:5566/64"),
						Gateway: mustParseIP("fe80::5044:55ff:fe66:7788"),
					},
				},
			},
		},
		{
			command:   cniserver.CNI_DEL,
			namespace: "namespace-slaac",
			name:      "pod1",
		},
	})
}

func TestPodNFVBridgedVLAN(t *testing.T) {
	if !runTestAsRoot(t) {
		return
	}

	runTestCommon(t, []*nfvOperation{
		{
			command:      cniserver.CNI_ADD,
			namespace:    "namespace1",
			name:         "pod1",
			createDummys: []string{"dummy0"},
			pod: &kapi.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"pod.network.openshift.io/nfv-select-sdn": "false",
						"pod.network.openshift.io/nfv-networks": `{
  "bv-test": {
    "addressing": {
      "ips": [
        {"ip": "192.168.1.5/24","gateway": "192.168.1.1"}
      ]
    },
    "interface": {
      "type": "bridged-vlan",
      "vlanId": 42,
      "ifname": "dummy0",
      "containerName": "eth1"
    }
  }
}`,
					},
				},
			},
			expectedLinks: []linkDesc{
				newVethLinkDesc("eth1", "192.168.1.5/24", "namespace1", "pod1"),
				newBridgeLinkDesc("br-vlan42", 42),
			},
			result: &cnicurrent.Result{
				Interfaces: []*cnicurrent.Interface{
					{
						Name: "eth1",
					},
				},
				IPs: []*cnicurrent.IPConfig{
					{
						Version: "4",
						Address: mustParseIPNet("192.168.1.5/24"),
						Gateway: net.ParseIP("192.168.1.1").To4(),
					},
				},
			},
		},
		{
			command:      cniserver.CNI_ADD,
			namespace:    "namespace2",
			name:         "pod1",
			pod: &kapi.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"pod.network.openshift.io/nfv-select-sdn": "false",
						"pod.network.openshift.io/nfv-networks": `{
  "bv-test2": {
    "addressing": {
      "ips": [
        {"ip": "192.168.1.6/24","gateway": "192.168.1.1"}
      ]
    },
    "interface": {
      "type": "bridged-vlan",
      "vlanId": 42,
      "ifname": "dummy0",
      "containerName": "eth1"
    }
  }
}`,
					},
				},
			},
			expectedLinks: []linkDesc{
				newVethLinkDesc("eth1", "192.168.1.6/24", "namespace2", "pod1"),
			},
			result: &cnicurrent.Result{
				Interfaces: []*cnicurrent.Interface{
					{
						Name: "eth1",
					},
				},
				IPs: []*cnicurrent.IPConfig{
					{
						Version: "4",
						Address: mustParseIPNet("192.168.1.6/24"),
						Gateway: net.ParseIP("192.168.1.1").To4(),
					},
				},
			},
		},
		{
			command:   cniserver.CNI_DEL,
			namespace: "namespace1",
			name:      "pod1",
		},
		{
			command:   cniserver.CNI_DEL,
			namespace: "namespace2",
			name:      "pod1",
		},
	})
}
