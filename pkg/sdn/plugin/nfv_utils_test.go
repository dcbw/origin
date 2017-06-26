package plugin

import (
	"fmt"
	"os"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

type fakeItem struct {
	name    string
	isDir   bool
	content []byte
}

func (i fakeItem) Name() string {
	return i.name
}

func (i fakeItem) Size() int64 {
	return int64(len(i.content))
}

func (i fakeItem) Mode() os.FileMode {
	return 0644
}

func (i fakeItem) ModTime() time.Time {
	return time.Now()
}

func (i fakeItem) IsDir() bool {
	return i.isDir
}

func (i fakeItem) Sys() interface{} {
	return i
}

type fakeFS struct {
	items map[string]fakeItem
}

var _ filesystem = &fakeFS{}

func (f fakeFS) ReadFile(filename string) ([]byte, error) {
	file, ok := f.items[filename]
	if !ok {
		return nil, &os.PathError{"read", filename, syscall.ENOENT}
	}
	return file.content, nil
}

func (f fakeFS) ReadDir(dirname string) ([]os.FileInfo, error) {
	if !strings.HasSuffix(dirname, "/") {
		dirname += "/"
	}

	files := make([]os.FileInfo, 0)
	for path, file := range f.items {
		if strings.HasPrefix(path, dirname) {
			files = append(files, file)
		}
	}
	if len(files) == 0 {
		return nil, &os.PathError{"readdir", dirname, syscall.ENOENT}
	}

	return files, nil
}

func makeCpuFile(num int) fakeItem {
	return fakeItem{
		name: fmt.Sprintf("cpu%d", num),
		isDir: true,
	}
}

func TestGetCpus(t *testing.T) {
	fs := fakeFS{
		items: map[string]fakeItem{
			"/sys/devices/system/cpu/cpu0": makeCpuFile(0),
			"/sys/devices/system/cpu/cpu1": makeCpuFile(1),
			"/sys/devices/system/cpu/cpu2": makeCpuFile(2),
			"/sys/devices/system/cpu/hotplug": fakeItem{
				name: "hotplug",
				isDir: true,
			},
			"/sys/devices/system/cpu/uevent": fakeItem{
				name: "uevent",
				isDir: false,
			},
		},
	}

	cpus, err := getCpus(fs, _PATH_SYS_CPU)
	if err != nil {
		t.Fatalf("unexpected error reading CPUs: %v", err)
	}
	if len(cpus) != 3 {
		t.Fatalf("unexpected number of CPUs %d (expected 3)", len(cpus))
	}
	if cpus[0] != 0 && cpus[1] != 1 && cpus[2] != 2 {
		t.Fatalf("unexpected returned CPUs: %v", cpus)
	}
}

func makeNodeFile(num int) fakeItem {
	return fakeItem{
		name: fmt.Sprintf("node%d", num),
		isDir: true,
	}
}

func TestGetTopology(t *testing.T) {
	fs := fakeFS{
		items: map[string]fakeItem{
			"/sys/devices/system/cpu/cpu0": makeCpuFile(0),
			"/sys/devices/system/cpu/cpu1": makeCpuFile(1),
			"/sys/devices/system/cpu/cpu2": makeCpuFile(2),
			"/sys/devices/system/cpu/cpu3": makeCpuFile(3),
			"/sys/devices/system/cpu/cpu4": makeCpuFile(4),
			"/sys/devices/system/cpu/cpu5": makeCpuFile(5),
			"/sys/devices/system/node/node0": makeNodeFile(0),
			"/sys/devices/system/node/node0/cpu0": makeCpuFile(0),
			"/sys/devices/system/node/node0/cpu1": makeCpuFile(1),
			"/sys/devices/system/node/node0/cpu4": makeCpuFile(4),
			"/sys/devices/system/node/node1": makeNodeFile(1),
			"/sys/devices/system/node/node1/cpu2": makeCpuFile(3),
			"/sys/devices/system/node/node1/cpu3": makeCpuFile(2),
			"/sys/devices/system/node/node1/cpu5": makeCpuFile(5),
			"/sys/devices/system/node/online": fakeItem{
				name: "online",
				isDir: false,
			},
			"/sys/devices/system/node/memory9": fakeItem{
				name: "memory9",
				isDir: true,
			},
		},
	}

	cpus, nodes, err := getTopology(fs)
	if err != nil {
		t.Fatalf("unexpected error reading NUMA nodes: %v", err)
	}

	expectedNodes := UintSlice{0,1}
	expectedCpus := map[uint]*Cpu{
		0: &Cpu{id:   0, numaNode: 0 },
		1: &Cpu{id:   1, numaNode: 0 },
		4: &Cpu{id:   4, numaNode: 0 },
		2: &Cpu{id:   2, numaNode: 1 },
		3: &Cpu{id:   3, numaNode: 1 },
		5: &Cpu{id:   5, numaNode: 1 },
	}
	if !reflect.DeepEqual(nodes, expectedNodes) {
		t.Fatalf("actual nodes %+v not equal to expected %+v", nodes, expectedNodes)
	}
	if len(cpus) != len(expectedCpus) {
		t.Fatalf("actual CPUs %+v not equal to expected %+v", cpus, expectedCpus)
	}
	for k, v := range cpus {
		expectedV, ok := expectedCpus[k]
		if !ok {
			t.Fatalf("couldn't find CPU %d in expected set", k)
		}
		if !reflect.DeepEqual(v, expectedV) {
		t.Fatalf("actual CPU %+v not equal to expected %+v", v, expectedV)
		}
	}
}

func TestSanitizeCPUList(t *testing.T) {
	testcases := []struct{
		input     string
		cpus      []uint
		expectErr bool
	}{
		{
			input: "1,2,3,4",
			cpus: []uint{1,2,3,4},
		},
		{
			input: "1",
			cpus: []uint{1},
		},
		{
			input: "",
			expectErr: true,
		},
		{
			input: "1,,,",
			expectErr: true,
		},
	}

	for i, tc := range testcases {
		cpus, err := parseUintList(tc.input)
		if tc.expectErr {
			if err == nil {
				t.Fatalf("case %d: expected error but got success", i)
			}
		} else {
			if err != nil {
				t.Fatalf("case %d: got unexpected error: %v", err)
			}
			if !cpus.Equal(tc.cpus) {
				t.Fatalf("case %d: expected cpus result %v but got %v", tc.cpus, cpus)
			}
		}
	}
}

func TestCPUAffinity(t *testing.T) {
	fs := fakeFS{
		items: map[string]fakeItem{
			"/sys/devices/system/cpu/cpu0": makeCpuFile(0),
			"/sys/devices/system/cpu/cpu1": makeCpuFile(1),
			"/sys/devices/system/cpu/cpu2": makeCpuFile(2),
			"/sys/devices/system/cpu/cpu3": makeCpuFile(3),
			"/sys/devices/system/cpu/cpu4": makeCpuFile(4),
			"/sys/devices/system/cpu/cpu5": makeCpuFile(5),
		},
	}

	testcases := []struct{
		containerID string
		containerName string
		affinityAnnotation string
		cpuset             string
		numFloating        int
		expectErr          bool
	}{
		{
			containerName: "foobar22",
			containerID: "27531eea-bfa7-4bb2-86d1-480665328aed",
			affinityAnnotation: "1,2,3,4,5",
			cpuset: "1,2,3,4,5",
			numFloating: 1,
		},
		{
			containerName: "foobar22",
			containerID: "27531eea-bfa7-4bb2-86d1-480665328aed",
			affinityAnnotation: "1,2",
			cpuset: "1,2",
			numFloating: 4,
		},
	}

	for i, tc := range testcases {
		m, err := newCPUManager(fs)
		if err != nil {
			t.Fatalf("error creating CPUManager: %v", err)
		}
		annotations := make(map[string]string)
		if tc.affinityAnnotation != "" {
			annotations[CPUAffinityAnnotation] = tc.affinityAnnotation
		}
		cpuset, _, err := m.Reserve("foobar", tc.containerName, annotations)
		if err != nil {
			if !tc.expectErr {
				t.Fatalf("%d: didn't expect error %v", i, err)
			}
		} else {
			if tc.expectErr {
				t.Fatalf("%d: expected error", i)
			}
			if tc.cpuset != cpuset {
				t.Fatalf("%d: expected cpuset %q but got %q", i, tc.cpuset, cpuset)
			}
		}

		err = m.Reconcile("foobar", tc.containerName, tc.containerID, func (containerID string, cpus, numas string) error {
			return fmt.Errorf("unexpected container reconcile")
		})
		if err != nil {
			t.Fatalf("%d: unexpected Reconcile error %v", err)
		}
		if tc.numFloating != len(m.cpuResources[FloatingResName].members) {
			t.Fatalf("%d: expected %d floating but got %d", i, tc.numFloating, len(m.cpuResources[FloatingResName].members))
		}
	}
}

func TestCPURequest(t *testing.T) {
	fs := fakeFS{
		items: map[string]fakeItem{
			"/sys/devices/system/cpu/cpu0": makeCpuFile(0),
			"/sys/devices/system/cpu/cpu1": makeCpuFile(1),
			"/sys/devices/system/cpu/cpu2": makeCpuFile(2),
			"/sys/devices/system/cpu/cpu3": makeCpuFile(3),
			"/sys/devices/system/cpu/cpu4": makeCpuFile(4),
			"/sys/devices/system/cpu/cpu5": makeCpuFile(5),
		},
	}

	testcases := []struct{
		containerID string
		containerName string
		resourceAnnotation string
		requestAnnotation  string
		numCpus            int
		numFloating        int
		expectErr          bool
	}{
		{
			containerName: "foobar22",
			containerID: "27531eea-bfa7-4bb2-86d1-480665328aed",
			resourceAnnotation: "blah:3",
			requestAnnotation: "blah",
			numCpus: 3,
			numFloating: 3,
		},
	}

	for i, tc := range testcases {
		m, err := newCPUManager(fs)
		if err != nil {
			t.Fatalf("error creating CPUManager: %v", err)
		}
		annotations := make(map[string]string)
		if tc.resourceAnnotation != "" {
			annotations[CPUResourceAnnotation] = tc.resourceAnnotation
		}
		if tc.requestAnnotation != "" {
			annotations[CPURequestAnnotation] = tc.requestAnnotation
		}
		cpuset, _, err := m.Reserve("foobar", tc.containerName, annotations)
		if err != nil {
			if !tc.expectErr {
				t.Fatalf("%d: didn't expect error %v", i, err)
			}
		} else {
			if tc.expectErr {
				t.Fatalf("%d: expected error", i)
			}
			cpus, err := parseUintList(cpuset)
			if err != nil {
				t.Fatalf("%d: error parsing cpuset: %v", i, err)
			}
			if tc.numCpus != len(cpus) {
				t.Fatalf("%d: expected cpuset length %d but got %d", i, tc.numCpus, len(cpus))
			}
		}

		err = m.Reconcile("foobar", tc.containerName, tc.containerID, func (containerID string, cpus, numas string) error {
			return fmt.Errorf("unexpected container reconcile")
		})
		if err != nil {
			t.Fatalf("%d: unexpected Reconcile error %v", err)
		}
		if tc.numFloating != len(m.cpuResources[FloatingResName].members) {
			t.Fatalf("%d: expected %d floating but got %d", i, tc.numFloating, len(m.cpuResources[FloatingResName].members))
		}
	}
}

func TestCPUFloatingContainerMoved(t *testing.T) {
	fs := fakeFS{
		items: map[string]fakeItem{
			"/sys/devices/system/cpu/cpu0": makeCpuFile(0),
			"/sys/devices/system/cpu/cpu1": makeCpuFile(1),
			"/sys/devices/system/cpu/cpu2": makeCpuFile(2),
			"/sys/devices/system/cpu/cpu3": makeCpuFile(3),
			"/sys/devices/system/cpu/cpu4": makeCpuFile(4),
			"/sys/devices/system/cpu/cpu5": makeCpuFile(5),
		},
	}

	m, err := newCPUManager(fs)
	if err != nil {
		t.Fatalf("error creating CPUManager: %v", err)
	}

	// Add a floating container
	cpuset, _, err := m.Reserve("foobar", "floating-container", make(map[string]string))
	if err != nil {
		t.Fatalf("unexpected error reserving CPUs for floating container: %v", err)
	}
	if cpuset != "0,1,2,3,4,5" {
		t.Fatalf("unexpected cpuset for floating container: %v", cpuset)
	}

	err = m.Reconcile("foobar", "floating-container", "27531eea-bfa7-4bb2-86d1-480665328aed", func (containerID string, cpus, numas string) error {
		return fmt.Errorf("unexpected container reconcile")
	})
	if err != nil {
		t.Fatalf("unexpected Reconcile error %v", err)
	}

	// Now add an exclusive container
	annotations := map[string]string{
		CPUResourceAnnotation: "blah:3",
		CPURequestAnnotation: "blah",
	}
	cpuset, _, err = m.Reserve("foobar", "exclusive-container", annotations)
	if err != nil {
		t.Fatalf("unexpected error reserving CPUs for exclusive container: %v", err)
	}

	exclusiveCpus, err := parseUintList(cpuset)
	if err != nil {
		t.Fatalf("error parsing cpuset: %v", err)
	}
	if len(exclusiveCpus) != 3 {
		t.Fatalf("expected cpuset length 3 but got %d", len(exclusiveCpus))
	}

	var floatingCpus UintSlice
	err = m.Reconcile("foobar", "exclusive-container", "6417e0eb-cd3e-426b-a467-e64bcbd41ad3", func (containerID string, cpus, numas string) error {
		if containerID == "floating-container" {
			floatingCpus, err = parseUintList(cpus)
			if err != nil {
				t.Fatalf("unexpected Reconcile error parsing floating cpuset %q: %v", cpus, err)
			}
			if len(floatingCpus) != 3 {
				t.Fatalf("unexpected floating cpuset length %q: %v", cpus, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected Reconcile error %v", err)
	}

	// Ensure no floating CPU is in the exclusive CPU list
	for _, fcpu := range floatingCpus {
		for _, ecpu := range exclusiveCpus {
			if fcpu == ecpu {
				t.Fatalf("unexpected overlap between floating %q and exclusive %q cpus", floatingCpus, exclusiveCpus)
			}
		}
	}
}

func addCpuToNode(nodePath string, cpu int, items *map[string]fakeItem) {
	cpuPath := fmt.Sprintf("%s/cpu%d", nodePath, cpu)
	(*items)[cpuPath] = makeCpuFile(cpu)
	cpuPath = fmt.Sprintf("/sys/devices/system/cpu/cpu%d", cpu)
	(*items)[cpuPath] = makeCpuFile(cpu)
}

func makeNumaFS(t *testing.T, numNodes, numCPUs int) fakeFS {
	if numCPUs < numNodes {
		t.Fatalf("must have more CPUs (%d) than nodes (%d)", numCPUs, numNodes)
	}

	items := make(map[string]fakeItem)
	var lastNodePath string
	for i := 0; i < numNodes; i++ {
		node := fmt.Sprintf("/sys/devices/system/node/node%d", i)
		items[node] = makeNodeFile(i)
		for j := 0; j < numCPUs / numNodes; j++ {
			addCpuToNode(node, j, &items)
		}
		lastNodePath = node
	}

	// Add any remaining CPUs to the last NUMA node
	for j := (numCPUs / numNodes) * numNodes; j < numCPUs; j++ {
		addCpuToNode(lastNodePath, j, &items)
	}

	return fakeFS{items: items}
}

func TestNUMAAffinity(t *testing.T) {
	fs := makeNumaFS(t, 2, 6)

	testcases := []struct{
		containerName string
		containerID string
		affinityAnnotation string
		numaset            string
		numFloating        int
		expectErr          bool
	}{
		{
			containerName: "foobar22",
			containerID: "6417e0eb-cd3e-426b-a467-e64bcbd41ad3",
			affinityAnnotation: "0",
			numaset: "0",
			numFloating: 1,
		},
		{
			containerName: "foobar22",
			containerID: "6417e0eb-cd3e-426b-a467-e64bcbd41ad3",
			affinityAnnotation: "0,1",
			numaset: "0,1",
			numFloating: 0,
		},
	}

	for i, tc := range testcases {
		m, err := newCPUManager(fs)
		if err != nil {
			t.Fatalf("error creating CPUManager: %v", err)
		}
		annotations := make(map[string]string)
		if tc.affinityAnnotation != "" {
			annotations[NUMAAffinityAnnotation] = tc.affinityAnnotation
		}
		_, numaset, err := m.Reserve("foobar", tc.containerName, annotations)
		if err != nil {
			if !tc.expectErr {
				t.Fatalf("%d: didn't expect error %v", i, err)
			}
		} else {
			if tc.expectErr {
				t.Fatalf("%d: expected error", i)
			}
			if tc.numaset != numaset {
				t.Fatalf("%d: expected cpuset %q but got %q", i, tc.numaset, numaset)
			}
		}

		err = m.Reconcile("foobar", tc.containerName, tc.containerID, func (containerID string, cpus, numas string) error {
			return fmt.Errorf("unexpected container reconcile")
		})
		if err != nil {
			t.Fatalf("%d: unexpected Reconcile error %v", err)
		}
		if tc.numFloating != len(m.numaResources[FloatingResName].members) {
			t.Fatalf("%d: expected %d floating but got %d", i, tc.numFloating, len(m.numaResources[FloatingResName].members))
		}
	}
}

func TestNUMARequest(t *testing.T) {
	fs := makeNumaFS(t, 2, 6)

	testcases := []struct{
		containerID string
		containerName string
		resourceAnnotation string
		requestAnnotation  string
		numNodes           int
		numFloating        int
		expectErr          bool
	}{
		{
			containerName: "foobar22",
			containerID: "6417e0eb-cd3e-426b-a467-e64bcbd41ad3",
			resourceAnnotation: "blah:2",
			requestAnnotation: "blah",
			numNodes: 2,
			numFloating: 0,
		},
	}

	for i, tc := range testcases {
		m, err := newCPUManager(fs)
		if err != nil {
			t.Fatalf("error creating CPUManager: %v", err)
		}
		annotations := make(map[string]string)
		if tc.resourceAnnotation != "" {
			annotations[NUMAResourceAnnotation] = tc.resourceAnnotation
		}
		if tc.requestAnnotation != "" {
			annotations[NUMARequestAnnotation] = tc.requestAnnotation
		}
		_, numaset, err := m.Reserve("foobar", tc.containerName, annotations)
		if err != nil {
			if !tc.expectErr {
				t.Fatalf("%d: didn't expect error %v", i, err)
			}
		} else {
			if tc.expectErr {
				t.Fatalf("%d: expected error", i)
			}
			nodes, err := parseUintList(numaset)
			if err != nil {
				t.Fatalf("%d: error parsing numaset: %v", i, err)
			}
			if tc.numNodes != len(nodes) {
				t.Fatalf("%d: expected numaset length %d but got %d", i, tc.numNodes, len(nodes))
			}
		}

		err = m.Reconcile("foobar", tc.containerName, tc.containerID, func (containerID string, cpus, numas string) error {
			return fmt.Errorf("unexpected container reconcile")
		})
		if err != nil {
			t.Fatalf("%d: unexpected Reconcile error %v", err)
		}
		if tc.numFloating != len(m.numaResources[FloatingResName].members) {
			t.Fatalf("%d: expected %d floating but got %d", i, tc.numFloating, len(m.numaResources[FloatingResName].members))
		}
	}
}

func TestNUMAFloatingContainerMoved(t *testing.T) {
	fs := makeNumaFS(t, 4, 8)

	m, err := newCPUManager(fs)
	if err != nil {
		t.Fatalf("error creating CPUManager: %v", err)
	}

	// Add a floating container
	_, numaset, err := m.Reserve("foobar", "floating-container", make(map[string]string))
	if err != nil {
		t.Fatalf("unexpected error reserving NUMA nodes for floating container: %v", err)
	}
	if numaset != "0,1,2,3" {
		t.Fatalf("unexpected numaset for floating container: %v", numaset)
	}

	err = m.Reconcile("foobar", "floating-container", "27531eea-bfa7-4bb2-86d1-480665328aed", func (containerID string, cpus, numas string) error {
		// No reserved nodes; so no change for floating containers
		return fmt.Errorf("unexpected container reconcile")
	})
	if err != nil {
		t.Fatalf("unexpected Reconcile error %v", err)
	}

	// Now add an exclusive container
	annotations := map[string]string{
		NUMAResourceAnnotation: "blah:2",
		NUMARequestAnnotation: "blah",
	}
	_, numaset, err = m.Reserve("foobar", "exclusive-container", annotations)
	if err != nil {
		t.Fatalf("unexpected error reserving NUMA nodes for exclusive container: %v", err)
	}

	exclusiveNodes, err := parseUintList(numaset)
	if err != nil {
		t.Fatalf("error parsing numaset: %v", err)
	}
	if len(exclusiveNodes) != 2 {
		t.Fatalf("expected numaset length 2 but got %d", len(exclusiveNodes))
	}

	var floatingNodes UintSlice
	err = m.Reconcile("foobar", "exclusive-container", "6417e0eb-cd3e-426b-a467-e64bcbd41ad3", func (containerID string, cpus, numas string) error {
		if containerID == "floating-container" {
			floatingNodes, err = parseUintList(numas)
			if err != nil {
				t.Fatalf("unexpected Reconcile error parsing floating numa nodes %q: %v", numas, err)
			}
			if len(floatingNodes) != 2 {
				t.Fatalf("unexpected floating numaset length %q: %v", numas, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected Reconcile error %v", err)
	}

	// Ensure no floating node is in the exclusive node list
	for _, fnode := range floatingNodes {
		for _, enode := range exclusiveNodes {
			if fnode == enode {
				t.Fatalf("unexpected overlap between floating %q and exclusive %q numa nodes", floatingNodes, exclusiveNodes)
			}
		}
	}
}

