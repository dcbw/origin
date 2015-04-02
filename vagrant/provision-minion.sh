#!/bin/bash
set -ex
source $(dirname $0)/provision-config.sh

MINION_IP=$4
OPENSHIFT_SDN=$6
MINION_INDEX=$5

NETWORK_CONF_PATH=/etc/sysconfig/network-scripts/

rm -f ${NETWORK_CONF_PATH}ifcfg-enp*

sed -i '/NM_CONTROLLED=no/d' ${NETWORK_CONF_PATH}ifcfg-eth0
sed -i 's/DEVICE=eth0/DEVICE=eth1/' ${NETWORK_CONF_PATH}ifcfg-eth0
mv ${NETWORK_CONF_PATH}ifcfg-eth0 ${NETWORK_CONF_PATH}ifcfg-eth1

cat <<EOF > ${NETWORK_CONF_PATH}ifcfg-eth0
DEVICE=eth0
ONBOOT=yes
TYPE=Ethernet
BOOTPROTO=dhcp
IPV6INIT=yes
EOF

rm -f /var/lib/NetworkManager/*.lease

# Setup hosts file to support ping by hostname to master
if [ ! "$(cat /etc/hosts | grep $MASTER_NAME)" ]; then
  echo "Adding $MASTER_NAME to hosts file"
  echo "$MASTER_IP $MASTER_NAME" >> /etc/hosts
fi

# Setup hosts file to support ping by hostname to each minion in the cluster
minion_ip_array=(${MINION_IPS//,/ })
for (( i=0; i<${#MINION_NAMES[@]}; i++)); do
  minion=${MINION_NAMES[$i]}
  ip=${minion_ip_array[$i]}  
  if [ ! "$(cat /etc/hosts | grep $minion)" ]; then
    echo "Adding $minion to hosts file"
    echo "$ip $minion" >> /etc/hosts
  fi  
done

yum -y install deltarpm

# Install the required packages
pushd /etc/yum.repos.d/
  if [ ! -f ipvlan-f20.repo ]; then
    wget -q http://people.redhat.com/dcbw/ipvlan-f20/ipvlan-f20.repo
  fi
  yum -y --disablerepo=* --enablerepo=ipvlan-f20 upgrade
popd
yum install -y docker-io git golang e2fsprogs hg openvswitch net-tools bridge-utils which ethtool

# Build openshift
echo "Building openshift"
cp -r /vagrant /tmp
pushd /tmp/vagrant
  ./hack/build-go.sh
  cp _output/local/go/bin/openshift /usr/bin
popd

# Copy over the certificates directory
cp -r /vagrant/openshift.local.config /
chown -R vagrant.vagrant /openshift.local.config

if [ "${OPENSHIFT_SDN}" != "ovs-gre" ]; then
  export ETCD_CAFILE=/openshift.local.config/master/ca.crt
  export ETCD_CERTFILE=/openshift.local.config/master/master.etcd-client.crt
  export ETCD_KEYFILE=/openshift.local.config/master/master.etcd-client.key
  $(dirname $0)/provision-node-sdn.sh $@
else
  # Setup default networking between the nodes
  $(dirname $0)/provision-gre-network.sh $@
fi

# get the minion name, index is 1-based
minion_name=${MINION_NAMES[$MINION_INDEX-1]}
# Create systemd service
cat <<EOF > /usr/lib/systemd/system/openshift-node.service
[Unit]
Description=OpenShift Node
Requires=network.service
After=docker.service network.service

[Service]
ExecStart=/usr/bin/openshift start node --network-plugin=redhat/openshift-ipvlan-subnet --config=/openshift.local.config/node-${minion_name}/node-config.yaml
Restart=on-failure
RestartSec=10s

[Install]
WantedBy=multi-user.target
EOF

# Start the service
systemctl daemon-reload
systemctl enable openshift-node.service
systemctl start openshift-node.service

# Set up the OPENSHIFTCONFIG environment variable for use by the client
echo 'export OPENSHIFTCONFIG=/openshift.local.config/master/admin.kubeconfig' >> /root/.bash_profile
echo 'export OPENSHIFTCONFIG=/openshift.local.config/master/admin.kubeconfig' >> /home/vagrant/.bash_profile

# Register with the master
#curl -X POST -H 'Accept: application/json' -d "{\"kind\":\"Minion\", \"id\":"${MINION_IP}", \"apiVersion\":\"v1beta1\", \"hostIP\":"${MINION_IP}" }" http://${MASTER_IP}:8080/api/v1beta1/minions
