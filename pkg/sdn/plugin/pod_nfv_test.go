package plugin

import (
	"fmt"
	"net"
	"os"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/openshift/origin/pkg/sdn/plugin/cniserver"

	kapi "k8s.io/kubernetes/pkg/api"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kexec "k8s.io/kubernetes/pkg/util/exec"

	"github.com/containernetworking/cni/pkg/ns"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	cnicurrent "github.com/containernetworking/cni/pkg/types/current"

	"github.com/vishvananda/netlink"
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
		name: name,
		linkType: linkType,
		ip: ip,
	}
}

func newVlanLinkDesc(name, ip string, vlanid uint) linkDesc {
	return linkDesc{
		name: name,
		linkType: "vlan",
		ip: ip,
		vlanid: vlanid,
	}
}

func newVethLinkDesc(name, ip, podNamespace, podName string) linkDesc {
	return linkDesc{
		name: name,
		linkType: "veth",
		ip: ip,
		podNamespace: podNamespace,
		podName:      podName,
	}
}

type nfvOperation struct {
	command   cniserver.CNICommand
	namespace string
	name      string
	pod       *kapi.Pod
	expectSDN bool
	expectNS  bool
	createLinks []string
	sfcLink   string
	podLinks  []linkDesc
	failStr   string // error string for failing the operation
	result    *cnicurrent.Result
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
					pod:       &kapi.Pod{
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
					command:   cniserver.CNI_ADD,
					namespace: "namespace1",
					name:      "pod2",
					expectNS:  true,
					createLinks: []string{"dummy0", "dummy1"},
					pod:       &kapi.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Annotations: map[string]string{
								"pod.network.openshift.io/nfv-select-sdn": "false",
								"pod.network.openshift.io/nfv-networks": `{
  "customer": {
    "addressing": {
      "type": "static",
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
      "type": "static",
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
						Routes:  []*cnitypes.Route{
							{
								Dst: mustParseIPNet("10.5.6.0/24"),
								GW: net.ParseIP("192.168.1.2").To4(),
							},
							{
								Dst: mustParseIPNet("172.16.0.0/16"),
								GW: net.ParseIP("192.168.1.3").To4(),
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
					command:   cniserver.CNI_ADD,
					namespace: "namespace1",
					name:      "pod3",
					expectNS:  true,
					createLinks: []string{"dummy2"},
					pod:       &kapi.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Annotations: map[string]string{
								"pod.network.openshift.io/nfv-select-sdn": "false",
								"pod.network.openshift.io/nfv-networks": `{
  "physdev": {
    "addressing": {
      "type": "static",
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
								Gateway: net.ParseIP("abcd:1234:ffff::cdd1"),
							},
						},
						Routes: []*cnitypes.Route{
							{
								Dst: mustParseIPNet("abbe:cafe::/64"),
								GW: net.ParseIP("abcd:1234:ffff::cdd2"),
							},
							{
								Dst: mustParseIPNet("aaaa:cccc::/64"),
								GW: net.ParseIP("abcd:1234:ffff::cdd3"),
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
					pod:       &kapi.Pod{
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
    "type": "static",
    "ips": [
      {"ip":"1.2.3.4/24"}
    ]
  },
  "remoteContainerName": "vrtr-link",
  "remoteAddressing": {
    "type": "static",
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
					pod:       &kapi.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Labels:      map[string]string{
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
					pod:       &kapi.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Labels:      map[string]string{
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
					pod:       &kapi.Pod{
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
    "type": "static",
    "ips": [
      {"ip":"1.2.3.4/24"}
    ]
  },
  "remoteContainerName": "vrtr-link",
  "remoteAddressing": {
    "type": "static",
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
					pod:       &kapi.Pod{
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
    "type": "static",
    "ips": [
      {"ip":"abcd:1234:ffff::1/128"}
    ]
  },
  "remoteContainerName": "vrtr-link",
  "remoteAddressing": {
    "type": "static",
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
					pod:       &kapi.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Labels:      map[string]string{
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
					command:   cniserver.CNI_ADD,
					namespace: "namespace5",
					name:      "pod1",
					expectNS:  true,
					createLinks: []string{"dummy0"},
					pod:       &kapi.Pod{
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
      "vfIndex": 0,
      "vfVlan": 1234,
      "ifname": "dummy0",
      "containerName": "eth1"
    }
  }
}`,
							},
						},
					},
					podLinks: []linkDesc{
						newLinkDesc("eth1", "sriov", "192.168.1.5/24"),
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
					command:   cniserver.CNI_DEL,
					namespace: "namespace5",
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
	nfv := NewNfvManager(fexec)

	for k, tc := range testcases {
		for opidx, op := range tc.operations {
			var testNS ns.NetNS
			var netnsPath string

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
				SandboxID:    fmt.Sprintf("%s.%s", op.namespace, op.name),
				Netns:        netnsPath,
			}

			var wantSDN bool
			var r cnitypes.Result
			err = originalNS.Do(func(ns.NetNS) error {
				switch op.command {
				case cniserver.CNI_ADD:
					wantSDN, r, err = nfv.nfvSetup(request, op.pod)
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
								return fmt.Errorf("setup got\n  %+v\n   %+v\n   %+v\nexpected\n  %+v\n   %+v\n   %+v", *result, result.IPs[0], result.Routes[0], *op.result, op.result.IPs[0], op.result.Routes[0])
							}
						} else if op.result != nil {
							return fmt.Errorf("expected result %v but got nil", op.result)
						}
					}
				case cniserver.CNI_DEL:
					wantSDN, err = nfv.nfvTeardown(request, netnsPath == "")
				}
				return err
			})
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
