package plugin

import (
	"fmt"
	"io/ioutil"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"sync"
"log"

	"github.com/golang/glog"
)

type filesystem interface {
	ReadFile(string) ([]byte, error)
	ReadDir(string) ([]os.FileInfo, error)
}

type realFS struct{}
var _ filesystem = &realFS{}

func (f realFS) ReadFile(filename string) ([]byte, error) {
	return ioutil.ReadFile(filename)
}

func (f realFS) ReadDir(dirname string) ([]os.FileInfo, error) {
	return ioutil.ReadDir(dirname)
}

const (
	_PATH_SYS_CPU string = "/sys/devices/system/cpu"
	_PATH_SYS_NUMA string = "/sys/devices/system/node"
)

func isDigitString(prefix, str string) bool {
	if !strings.HasPrefix(str, prefix) {
		return false
	}
	for _, c := range str[len(prefix):] {
		if !unicode.IsDigit(c) {
			return false
		}
	}
	return true
}

type UintSlice []uint
func (p UintSlice) Len() int           { return len(p) }
func (p UintSlice) Less(i, j int) bool { return p[i] < p[j] }
func (p UintSlice) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }

func (p UintSlice) Equal(other UintSlice) bool {
	if len(p) != len(other) {
		return false
	}
	for i, num := range p {
		if other[i] != num {
			return false
		}
	}
	return true
}

func (p UintSlice) Find(n uint) bool {
	for _, e := range p {
		if e == n {
			return true
		}
	}
	return false
}

func getCpus(fs filesystem, dirpath string) (UintSlice, error) {
	items, err := fs.ReadDir(dirpath)
	if err != nil {
		return nil, err
	}

	cpus := make(UintSlice, 0)
	for _, item := range items {
		if !item.IsDir() || !isDigitString("cpu", item.Name()) {
			continue
		}
		num, err := strconv.Atoi(item.Name()[len("cpu"):])
		if err != nil {
			return nil, fmt.Errorf("failed to read cpu item %s", item.Name())
		}
		cpus = append(cpus, uint(num))
	}
	sort.Sort(cpus)
	return cpus, nil
}

type Cpu struct {
	id       uint
	numaNode uint
}

func getTopology(fs filesystem) (map[uint]*Cpu, UintSlice, error) {
	cpuList, err := getCpus(fs, _PATH_SYS_CPU)
	if err != nil {
		return nil, nil, err
	}

	cpus := make(map[uint]*Cpu)
	for _, cpuID := range cpuList {
		cpus[cpuID] = &Cpu{
			id: cpuID,
			numaNode: 0,
		}
	}

	// Inspect NUMA topology, if present
	numaNodes := make(UintSlice, 0)
	items, err := fs.ReadDir(_PATH_SYS_NUMA)
	if err == nil {
		for _, item := range items {
			if !item.IsDir() || !isDigitString("node", item.Name()) {
				continue
			}
			num, err := strconv.Atoi(item.Name()[len("node"):])
			if err != nil {
				return nil, nil, fmt.Errorf("failed to read node item %s", item.Name())
			}
			path := fmt.Sprintf("%s/%s", _PATH_SYS_NUMA, item.Name())
			cpuList, err = getCpus(fs, path)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to read cpu item %s", path)
			}
			numaNodes = append(numaNodes, uint(num))
			for _, cpuID := range cpuList {
				if cpu, ok := cpus[cpuID]; ok {
					cpu.numaNode = uint(num)
				}
			}
		}
		sort.Sort(numaNodes)
	}
	if len(numaNodes) == 0 {
		numaNodes = append(numaNodes, 0)
	}

	return cpus, numaNodes, nil
}

type cpu struct {
	Cpu
	exclusive *resource
}

type numa struct {
	id uint
	exclusive *resource
	cpus []*cpu
}

type resourceType string

const (
	ResourceTypeCPU resourceType = "cpu"
	ResourceTypeNUMA resourceType = "numa"
)

type resource struct {
	rtype      resourceType
	name       string
	members    UintSlice
	containers []string
}

func (r *resource) makeSet() string {
	set := make([]string, 0, len(r.members))
	for _, m := range r.members {
		set = append(set, fmt.Sprintf("%d", m))
	}
	return strings.Join(set, ",")
}

func (r *resource) addContainerToCPU(containerID string, exclusive bool, cpus map[uint]*cpu) {
	if _, ok := stringInList(containerID, &r.containers); ok {
		panic("already in list")
	}
	r.containers = append(r.containers, containerID)
	if exclusive {
		for _, cpuNum := range r.members {
			cpus[cpuNum].exclusive = r
		}
	}
}

func (r *resource) addContainerToNUMANode(containerID string, exclusive bool, nodes map[uint]*numa) {
	if _, ok := stringInList(containerID, &r.containers); ok {
		panic("already in list")
	}
	r.containers = append(r.containers, containerID)
	if exclusive {
		for _, nodeID := range r.members {
			nodes[nodeID].exclusive = r
		}
	}
}

// returns <found> and <number containers>
func (r *resource) removeContainer(containerID string) (bool, bool) {
	if i, ok := stringInList(containerID, &r.containers); ok {
		r.containers = append(r.containers[:i], r.containers[i+1:]...)
		return true, len(r.containers) == 0
	}
	return false, false
}

type CPUManager struct {
	sync.Mutex

	cpus map[uint]*cpu
	cpuResources map[string]*resource
	// Map of containerID :: to-be-created resource name
	cpuPending map[string]string

	numaNodes map[uint]*numa
	numaResources map[string]*resource
	// Map of containerID :: to-be-created resource name
	numaPending map[string]string
}

func NewCPUManager() (*CPUManager, error) {
	return newCPUManager(realFS{})
}

const FloatingResName string = "floating"

func newCPUManager(fs filesystem) (*CPUManager, error) {
	m := &CPUManager{
		cpus:  make(map[uint]*cpu, 0),
		cpuResources: make(map[string]*resource),
		cpuPending: make(map[string]string),
		numaNodes:  make(map[uint]*numa, 0),
		numaResources: make(map[string]*resource),
		numaPending: make(map[string]string),
	}
	cpus, numaNodes, err := getTopology(fs)
	if err != nil {
		return nil, err
	}

	cpuList := make(UintSlice, 0)
	for _, c := range cpus {
		cpuList = append(cpuList, c.id)
	}
	sort.Sort(cpuList)

	m.cpuResources[FloatingResName] = &resource{
		rtype: ResourceTypeCPU,
		name: FloatingResName,
		members: cpuList,
	}

	for _, c := range cpus {
		m.cpus[c.id] = &cpu{Cpu: *c}
	}

	// NUMA
	m.numaResources[FloatingResName] = &resource{
		rtype: ResourceTypeNUMA,
		name: FloatingResName,
		members: numaNodes,
	}

	for _, n := range numaNodes {
		m.numaNodes[n] = &numa{id: n}
	}

	return m, nil
}

const (
	// Specific comma-separated CPU numbers to put this container on.
	// e.g. "1,2,3" or "0,4,5".  Other containers without explicit affinity
	// will be moved.
	CPUAffinityAnnotation          = "pod.network.openshift.io/cpu-affinity"
	// The resource name this container should use for CPU allocation
	CPURequestAnnotation           = "pod.network.openshift.io/cpu-request"
	// Defines a CPU resource that containers can use to reserve or share
	// CPUs.  Format:
	// <name>:<num cpus>
	CPUResourceAnnotation          = "pod.network.openshift.io/cpu-resource"

	// Specific comma-separated NUMA node numbers to put this container on.
	// e.g. "1,2,3" or "0,4,5".  Other containers without explicit affinity
	// will be moved.
	NUMAAffinityAnnotation          = "pod.network.openshift.io/numa-affinity"
	// The resource name this container should use for NUMA node allocation
	NUMARequestAnnotation           = "pod.network.openshift.io/numa-request"
	// Defines a NUMA resource that containers can use to reserve or share
	// NUMA nodes.  Format:
	// <name>:<num nodes>
	NUMAResourceAnnotation          = "pod.network.openshift.io/numa-resource"

)

func parseUintList(list string) (UintSlice, error) {
	nums := make(UintSlice, 0)
	split := strings.Split(list, ",")
	for _, n := range split {
		num, err := strconv.ParseUint(n, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CPU affinity annotation %q: %v", list, err)
		}
		nums = append(nums, uint(num))
	}
	if len(nums) == 0 {
		return nil, fmt.Errorf("failed to parse CPU affinity annotation %q: bad format", list)
	}
	return nums, nil
}

func uintInList(needle uint, haystack UintSlice) bool {
	for _, item := range haystack {
		if needle == item {
			return true
		}
	}
	return false
}

func stringInList(needle string, haystack *[]string) (int, bool) {
	for i, item := range *haystack {
		if needle == item {
			return i, true
		}
	}
	return -1, false
}

func (m *CPUManager) handleCPUAffinityAnnotation(containerKey, affinity string) (string, error) {
	cpus, err := parseUintList(affinity)
	if err != nil {
		return "", err
	}

	sort.Sort(cpus)
	res := &resource{
		rtype: ResourceTypeCPU,
		name:  containerKey,
		members: cpus,
	}

	// Validate the request
	for _, cpuID := range cpus {
		cpu, ok := m.cpus[cpuID]
		if !ok {
			return "", fmt.Errorf("cpu %d doesn't exist", cpuID)
		}
		if cpu.exclusive != nil {
			return "", fmt.Errorf("cpu %d already has exclusive users", cpuID)
		}
	}

	res.addContainerToCPU(containerKey, true, m.cpus)
	m.cpuResources[res.name] = res
	return res.makeSet(), nil
}

func (m *CPUManager) handleCPURequestAnnotation(namespace, containerKey, annotation string) (string, error) {
	resName, err := makeResourceName(namespace, annotation)
	if err != nil {
		return "", err
	}

	res, ok := m.cpuResources[resName]
	if !ok {
		// Resource not defined yet; float the container on all
		// available CPUs until it does show up
		res = m.cpuResources[FloatingResName]

		// Add a pending resource record so we can add this container
		// to the resource when it shows up
		m.cpuPending[containerKey] = resName
	}

	res.addContainerToCPU(containerKey, true, m.cpus)
	return res.makeSet(), nil
}

func (m *CPUManager) findFreeExclusiveCPU(ignoreCPUs UintSlice) (uint, error) {
	for _, cpu := range m.cpus {
		if !ignoreCPUs.Find(cpu.id) && cpu.exclusive == nil {
			return cpu.id, nil
		}
	}
	return 0, fmt.Errorf("no available exclusive CPU")
}

func (m *CPUManager) handleNUMAAffinityAnnotation(containerKey, affinity string) (string, error) {
	nodes, err := parseUintList(affinity)
	if err != nil {
		return "", err
	}

	sort.Sort(nodes)
	res := &resource{
		rtype: ResourceTypeNUMA,
		name:  containerKey,
		members: nodes,
	}

	// Validate the request
	for _, nodeID := range nodes {
		node, ok := m.numaNodes[nodeID]
		if !ok {
			return "", fmt.Errorf("NUMA node %d doesn't exist", nodeID)
		}
		if node.exclusive != nil {
			return "", fmt.Errorf("NUMA node %d already has exclusive users", nodeID)
		}
	}

	res.addContainerToNUMANode(containerKey, true, m.numaNodes)
	m.numaResources[res.name] = res
	return res.makeSet(), nil
}

func (m *CPUManager) handleNUMARequestAnnotation(namespace, containerKey, annotation string) (string, error) {
	resName, err := makeResourceName(namespace, annotation)
	if err != nil {
		return "", err
	}

	res, ok := m.numaResources[resName]
	if !ok {
		// Resource not defined yet; float the container on all
		// available NUMA nodes until it does show up
		res = m.numaResources[FloatingResName]

		// Add a pending resource record so we can add this container
		// to the resource when it shows up
		m.numaPending[containerKey] = resName
	}

	res.addContainerToNUMANode(containerKey, true, m.numaNodes)
	return res.makeSet(), nil
}

func (m *CPUManager) findFreeExclusiveNUMANode(ignoreNodes UintSlice) (uint, error) {
	for _, node := range m.numaNodes {
		if !ignoreNodes.Find(node.id) && node.exclusive == nil {
			return node.id, nil
		}
	}
	return 0, fmt.Errorf("no available exclusive NUMA node")
}

func createResource(rtype resourceType, namespace, resourceAnnotation, requestAnnotation string, annotations map[string]string) (*resource, uint, error) {
	// parse the resource definition
	resourceDesc, ok := annotations[resourceAnnotation]
	if !ok {
		return nil, 0, nil
	}
	descItems := strings.Split(resourceDesc, ":")
	if len(descItems) != 2 || descItems[0] == "" || descItems[1] == "" {
		return nil, 0, fmt.Errorf("invalid %s resource annotation %q", rtype, resourceDesc)
	}
	resName, err := makeResourceName(namespace, descItems[0])
	if err != nil {
		return nil, 0, err
	}
	numItems, err := strconv.Atoi(descItems[1])
	if err != nil {
		return nil, 0, fmt.Errorf("failed to parse %s resource %q num %q: %v", rtype, descItems[0], descItems[1], err)
	}
	if numItems == 0 {
		return nil, 0, fmt.Errorf("%s resource %q must request CPUs", rtype, descItems[0])
	}

	// Ensure pod that defines the resource also requests the same resource
	request, ok := annotations[requestAnnotation]
	if !ok {
		return nil, 0, fmt.Errorf("pod that defines %s resource must request a resource", rtype)
	}
	podRequestResName, err := makeResourceName(namespace, request)
	if err != nil {
		return nil, 0, err
	} else if podRequestResName != resName {
		return nil, 0, fmt.Errorf("pod that defines %s resource must also request it", rtype)
	}

	return &resource{
		rtype: rtype,
		name: resName,
	}, uint(numItems), nil
}

func (m *CPUManager) handleCPUResourceAnnotation(namespace string, annotations map[string]string, numa *resource) (*resource, error) {
	res, numCpus, err := createResource(ResourceTypeCPU, namespace, CPUResourceAnnotation, CPURequestAnnotation, annotations)
	if err != nil || res == nil{
		return nil, err
	}
	if _, ok := m.cpuResources[res.name]; ok {
		return nil, fmt.Errorf("resource name %q already exists", res.name)
	}

	// Reserve CPU resources
	// TODO: do something smart like try to fulfill request from cores on
	// the same socket
	// If a NUMA resource is given, try to fulfill request from cores in
	// those NUMA nodes
	for i := 0; i < int(numCpus); i++ {
		cpuID, err := m.findFreeExclusiveCPU(res.members)
		if err != nil {
			return nil, fmt.Errorf("couldn't find %d exclusive CPUs", numCpus)
		}
		res.members = append(res.members, cpuID)
	}
	sort.Sort(res.members)
	for _, cpuID := range res.members {
		m.cpus[cpuID].exclusive = res
	}

	// Add any pending containers to this resource
	for containerID, name := range m.cpuPending {
		if name == res.name {
			res.addContainerToCPU(containerID, true, m.cpus)
			delete(m.cpuPending, containerID)
		}
	}

	m.cpuResources[res.name] = res
	return res, nil
}

func (m *CPUManager) handleNUMAResourceAnnotation(namespace string, annotations map[string]string) (*resource, error) {
	res, numNodes, err := createResource(ResourceTypeNUMA, namespace, NUMAResourceAnnotation, NUMARequestAnnotation, annotations)
	if err != nil || res == nil {
		return nil, err
	}
log.Println("### 1 res %+v numNodes %d", res, numNodes)
	if _, ok := m.numaResources[res.name]; ok {
		return nil, fmt.Errorf("resource name %q already exists", res.name)
	}
log.Println("### 2")

	// Reserve NUMA resources
	for i := 0; i < int(numNodes); i++ {
		nodeID, err := m.findFreeExclusiveNUMANode(res.members)
		if err != nil {
			return nil, fmt.Errorf("couldn't find %d exclusive NUMA nodes", numNodes)
		}
		res.members = append(res.members, nodeID)
	}
log.Println("### 3")
	sort.Sort(res.members)
	for _, nodeID := range res.members {
		m.numaNodes[nodeID].exclusive = res
	}

log.Println("### 4")
	// Add any pending containers to this resource
	for containerID, name := range m.numaPending {
		if name == res.name {
			res.addContainerToNUMANode(containerID, true, m.numaNodes)
			delete(m.numaPending, containerID)
		}
	}

log.Println("### 5")
	m.numaResources[res.name] = res
	return res, nil
}

func makeResourceName(namespace, name string) (string, error) {
	if namespace == "" || name == "" {
		return "", fmt.Errorf("invalid resource name %q/%q", namespace, name)
	}
	return fmt.Sprintf("%s/%s", namespace, name), nil
}

// Create CPU/NUMA reservations which will be committed by Reconcile().  Returns
// cpulist and numanode strings (eg, "0,1,3,5").
// Takes a container name rather than ID because the container hasn't been created yet.
// The name will be swapped with the ID during Reconcile()
func (m *CPUManager) Reserve(namespace, containerName string, annotations map[string]string) (string, string, error) {
	m.Lock()
	defer m.Unlock()

	numaRes, err := m.handleNUMAResourceAnnotation(namespace, annotations)
	if err != nil {
		return "", "", err
	}

	containerKey := fmt.Sprintf("%s/%s", namespace, containerName)

	var finalNumaset string
	if numaset, ok := annotations[NUMAAffinityAnnotation]; ok {
		finalNumaset, err = m.handleNUMAAffinityAnnotation(containerKey, numaset)
	} else if request, ok := annotations[NUMARequestAnnotation]; ok {
		finalNumaset, err = m.handleNUMARequestAnnotation(namespace, containerKey, request)
	} else {
		numaRes := m.numaResources[FloatingResName]
		numaRes.addContainerToNUMANode(containerKey, false, m.numaNodes)
		finalNumaset = numaRes.makeSet()
	}
	if err != nil {
		m.releaseResource(numaRes)
		return "", "", err
	}

	cpuRes, err := m.handleCPUResourceAnnotation(namespace, annotations, numaRes)
	if err != nil {
		return "", "", err
	}

	var finalCpuset string
	if cpuset, ok := annotations[CPUAffinityAnnotation]; ok {
		finalCpuset, err = m.handleCPUAffinityAnnotation(containerKey, cpuset)
	} else if request, ok := annotations[CPURequestAnnotation]; ok {
		finalCpuset, err = m.handleCPURequestAnnotation(namespace, containerKey, request)
	} else {
		cpuRes := m.cpuResources[FloatingResName]
		cpuRes.addContainerToCPU(containerKey, false, m.cpus)
		finalCpuset = cpuRes.makeSet()
	}
	if err != nil {
		m.releaseResource(cpuRes)
		m.releaseResource(numaRes)
		return "", "", err
	}

	return finalCpuset, finalNumaset, err
}

func (m *CPUManager) releaseResource(res *resource) {
	if res.rtype == ResourceTypeCPU {
		for _, cpu := range m.cpus {
			if cpu.exclusive == res {
				cpu.exclusive = nil
			}
		}
		delete(m.cpuResources, res.name)
	} else if res.rtype == ResourceTypeNUMA {
		for _, node := range m.numaNodes {
			if node.exclusive == res {
				node.exclusive = nil
			}
		}
		delete(m.numaResources, res.name)
	}
}

// Release a CPU reservation
func (m *CPUManager) Release(containerID string) {
	m.Lock()
	defer m.Unlock()

	for _, res := range m.cpuResources {
		found, empty := res.removeContainer(containerID)
		if found && empty {
			m.releaseResource(res)
		}
	}
	delete(m.cpuPending, containerID)

	for _, res := range m.numaResources {
		found, empty := res.removeContainer(containerID)
		if found && empty {
			m.releaseResource(res)
		}
	}

	delete(m.numaPending, containerID)
}

type ReconcileFunc func(containerID string, cpus, numas string) error

// Expand or contract the floating container set as needed when exclusive
// containers are added or removed from CPUs and NUMA nodes
func (m *CPUManager) Reconcile(namespace, containerName, containerID string, fn ReconcileFunc) error {
	m.Lock()
	defer m.Unlock()

	containerKey := fmt.Sprintf("%s/%s", namespace, containerName)

	// If name was given, find it and update to a container ID
	for _, r := range m.cpuResources {
		for i, item := range r.containers {
			if item == containerKey {
				r.containers = append(r.containers[:i], r.containers[i+1:]...)
				r.containers = append(r.containers, containerID)
			}
		}
	}
	if v, ok := m.cpuPending[containerKey]; ok {
		delete(m.cpuPending, containerKey)
		m.cpuPending[containerID] = v
	}

	for _, r := range m.numaResources {
		for i, item := range r.containers {
			if item == containerKey {
				r.containers = append(r.containers[:i], r.containers[i+1:]...)
				r.containers = append(r.containers, containerID)
			}
		}
	}
	if v, ok := m.numaPending[containerKey]; ok {
		delete(m.numaPending, containerKey)
		m.numaPending[containerID] = v
	}

	type update struct {
		cpuset string
		numaset string
	}
	updates := make(map[string]*update)

	cpuFloating := make(UintSlice, 0, len(m.cpus))
	for _, cpu := range m.cpus {
		if cpu.exclusive == nil {
			cpuFloating = append(cpuFloating, cpu.id)
		}
	}
	sort.Sort(cpuFloating)

	f := m.cpuResources[FloatingResName]
	if !f.members.Equal(cpuFloating) {
		f.members = cpuFloating
		cpuSet := f.makeSet()
		for _, containerID := range f.containers {
			updates[containerID] = &update{cpuset: cpuSet}
		}
	}

	numaFloating := make(UintSlice, 0, len(m.numaNodes))
	for _, node := range m.numaNodes {
		if node.exclusive == nil {
			numaFloating = append(numaFloating, node.id)
		}
	}
	sort.Sort(numaFloating)

	f = m.numaResources[FloatingResName]
	if !f.members.Equal(numaFloating) {
		f.members = numaFloating
		numaSet := f.makeSet()
		for _, containerID := range f.containers {
			u, ok := updates[containerID]
			if !ok {
				u = &update{}
				updates[containerID] = u
			}
			u.numaset = numaSet
		}
	}

	for containerID, u := range updates {
		if err := fn(containerID, u.cpuset, u.numaset); err != nil {
			glog.Errorf("failed to update container %q cpuset=%q/numaset=%q: %v", containerID, u.cpuset, u.numaset, err)
		}
	}

	return nil
}
