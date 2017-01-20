package plugin

import (
	"fmt"
	"sync"
	"time"

	log "github.com/golang/glog"

	kapi "k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/client/cache"
	utilwait "k8s.io/kubernetes/pkg/util/wait"

	osclient "github.com/openshift/origin/pkg/client"
	osapi "github.com/openshift/origin/pkg/sdn/api"
)

type nodeVNIDMap struct {
	policy   osdnPolicy
	osClient *osclient.Client

	// Synchronizes add or remove ids/namespaces
	lock       sync.Mutex
	ids        map[string]uint32
	// Map of VNID :: map of name :: multicast enabled
	namespaces map[uint32]map[string]bool
}

func newNodeVNIDMap(policy osdnPolicy, osClient *osclient.Client) *nodeVNIDMap {
	return &nodeVNIDMap{
		policy:     policy,
		osClient:   osClient,
		ids:        make(map[string]uint32),
		namespaces: make(map[uint32]map[string]bool),
	}
}

func (vmap *nodeVNIDMap) addNamespaceToSet(name string, vnid uint32) {
	nsMap, ok := vmap.namespaces[vnid]
	if !ok {
		nsMap = make(map[string]bool)
		vmap.namespaces[vnid] = nsMap
	}
	nsMap[name] = false
}

func (vmap *nodeVNIDMap) removeNamespaceFromSet(name string, vnid uint32) {
	if nsMap, found := vmap.namespaces[vnid]; found {
		delete(nsMap, name)
		if len(nsMap) == 0 {
			delete(vmap.namespaces, vnid)
		}
	}
}

func (vmap *nodeVNIDMap) GetNamespaces(id uint32) []string {
	vmap.lock.Lock()
	defer vmap.lock.Unlock()

	if nsMap, ok := vmap.namespaces[id]; ok {
		names := make([]string, 0, len(nsMap))
		for name := range nsMap {
			names = append(names, name)
		}
		return names
	} else {
		return nil
	}
}

func (vmap *nodeVNIDMap) GetVNID(name string) (uint32, bool, error) {
	vmap.lock.Lock()
	defer vmap.lock.Unlock()

	if id, ok := vmap.ids[name]; ok {
		return id, vmap.vnidMulticastEnabled(id), nil
	}
	return 0, false, fmt.Errorf("Failed to find netid for namespace: %s in vnid map", name)
}

func (vmap *nodeVNIDMap) vnidMulticastEnabled(id uint32) bool {
	nsMap, ok := vmap.namespaces[id]
	if !ok || len(nsMap) == 0 {
		return false
	}

	// Multicast is only enabled for the VNID if all net namespaces enable it
	for _, nsEnabled := range nsMap {
		if !nsEnabled {
			return false
		}
	}
	return true
}

func (vmap *nodeVNIDMap) updateVNIDMulticastEnabled(name string, mcEnabled bool) bool {
	vmap.lock.Lock()
	defer vmap.lock.Unlock()

	id, ok := vmap.ids[name]
	if !ok {
		return false
	}
	return true
}

// Nodes asynchronously watch for both NetNamespaces and services
// NetNamespaces populates vnid map and services/pod-setup depend on vnid map
// If for some reason, vnid map propagation from master to node is slow
// and if service/pod-setup tries to lookup vnid map then it may fail.
// So, use this method to alleviate this problem. This method will
// retry vnid lookup before giving up.
func (vmap *nodeVNIDMap) WaitAndGetVNID(name string) (uint32, bool, error) {
	var id uint32
	var mcEnabled bool
	backoff := utilwait.Backoff{
		Duration: 100 * time.Millisecond,
		Factor:   1.5,
		Steps:    5,
	}
	err := utilwait.ExponentialBackoff(backoff, func() (bool, error) {
		var err error
		id, mcEnabled, err = vmap.GetVNID(name)
		return err == nil, nil
	})
	if err == nil {
		return id, mcEnabled, nil
	} else {
		return 0, false, fmt.Errorf("Failed to find netid for namespace: %s in vnid map", name)
	}
}

// Returns the old VNID and whether that VNID is valid
func (vmap *nodeVNIDMap) setVNID(name string, id uint32) (uint32, bool) {
	vmap.lock.Lock()
	defer vmap.lock.Unlock()

	oldId, found := vmap.ids[name];
	if found {
		vmap.removeNamespaceFromSet(name, oldId)
	}
	vmap.ids[name] = id
	vmap.addNamespaceToSet(name, id)

	log.Infof("Associate netid %d to namespace %q", id, name)

	return oldId, found
}

// Returns the old VNID
func (vmap *nodeVNIDMap) unsetVNID(name string) (uint32, error) {
	vmap.lock.Lock()
	defer vmap.lock.Unlock()

	id, found := vmap.ids[name]
	if !found {
		return 0, fmt.Errorf("Failed to find netid for namespace: %s in vnid map", name)
	}
	vmap.removeNamespaceFromSet(name, id)
	delete(vmap.ids, name)
	log.Infof("Dissociate netid %d from namespace %q", id, name)
	return id, nil
}

func netnsIsMulticastEnabled(netns *osapi.NetNamespace) bool {
	enabled, ok := netns.Annotations[osapi.MulticastEnabledAnnotation]
	return enabled == "true" && ok
}

func (vmap *nodeVNIDMap) populateVNIDs() error {
	nets, err := vmap.osClient.NetNamespaces().List(kapi.ListOptions{})
	if err != nil {
		return err
	}

	for _, net := range nets.Items {
		vmap.setVNID(net.Name, net.NetID)
		vmap.updateVNIDMulticastEnabled(net.Name, netnsIsMulticastEnabled(&net))
	}
	return nil
}

func (vmap *nodeVNIDMap) Start() error {
	// Populate vnid map synchronously so that existing services can fetch vnid
	err := vmap.populateVNIDs()
	if err != nil {
		return err
	}

	go utilwait.Forever(vmap.watchNetNamespaces, 0)
	return nil
}

func (vmap *nodeVNIDMap) watchNetNamespaces() {
	RunEventQueue(vmap.osClient, NetNamespaces, func(delta cache.Delta) error {
		netns := delta.Object.(*osapi.NetNamespace)

		log.V(5).Infof("Watch %s event for NetNamespace %q", delta.Type, netns.ObjectMeta.Name)
		switch delta.Type {
		case cache.Sync, cache.Added, cache.Updated:
			// Skip this event if the old and new network ids are same
			oldNetID, oldMCEnabled, err := vmap.GetVNID(netns.NetName)
			if err == nil {
				if oldNetID == netns.NetID && oldMCEnabled == netnsIsMulticastEnabled(netns) {
					break
				}
			}
			vmap.setVNID(netns.NetName, netns.NetID)
			newMCEnabled := vmap.vnidMulticastEnabled(netns.NetID)

			if delta.Type == cache.Added {
				vmap.policy.AddNetNamespace(netns, newMCEnabled)
			} else {
				vmap.policy.UpdateNetNamespace(netns, newMCEnabled, oldNetID, oldMCEnabled)
			}
		case cache.Deleted:
			vmap.unsetVNID(netns.NetName)
			vmap.policy.DeleteNetNamespace(netns, vmap.vnidMulticastEnabled(netns.NetID))
		}
		return nil
	})
}
