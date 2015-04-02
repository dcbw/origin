#!/bin/bash
set -ex
source $(dirname $0)/provision-config.sh
MINION_IP=$4

pushd $HOME
# build openshift-sdn
if [ -d openshift-sdn ]; then
    cd openshift-sdn
    git fetch origin
    git checkout dcbw/ipvlan
    git reset --hard origin/dcbw/ipvlan
else
    git clone https://github.com/dcbw/openshift-sdn.git
    cd openshift-sdn
    git checkout dcbw/ipvlan
fi

make clean
make
make install
popd

# Create systemd service
cat <<EOF > /usr/lib/systemd/system/openshift-node-sdn.service
[Unit]
Description=openshift SDN node
Requires=openvswitch.service
After=openvswitch.service
Before=openshift-node.service

[Service]
ExecStart=/usr/bin/openshift-sdn -minion -kubenet=ipvlan-l2 -etcd-endpoints=https://${MASTER_IP}:4001 -public-ip=${MINION_IP} -etcd-keyfile=${ETCD_KEYFILE} -etcd-certfile=${ETCD_CERTFILE} -etcd-cafile=${ETCD_CAFILE}

[Install]
WantedBy=multi-user.target
EOF

# Start the service
systemctl daemon-reload
systemctl enable openvswitch
systemctl start openvswitch
systemctl enable openshift-node-sdn.service
systemctl start openshift-node-sdn.service
