# Written by Sinter. One file for every chassis; on a compute node controller_ip is the controller.
[DEFAULT]
nova_metadata_host = {{ vars.controller_ip }}
metadata_proxy_shared_secret = {{ vars.metadata_proxy_secret }}

# The agent spawns haproxy inside the ovnmeta namespace through a root helper. These two keys belong
# to [AGENT], not [DEFAULT]: put in the wrong section they are read as the built-in default `sudo`,
# the sudoers rule EL ships only covers neutron-rootwrap, and a guest cannot reach 169.254.169.254.
[AGENT]
root_helper = sudo neutron-rootwrap /etc/neutron/rootwrap.conf
root_helper_daemon = sudo neutron-rootwrap-daemon /etc/neutron/rootwrap.conf

# The agent runs as `neutron`; /var/run/openvswitch/db.sock is root-only. Use the loopback manager.
[ovs]
ovsdb_connection = tcp:127.0.0.1:6640

[ovn]
ovn_sb_connection = tcp:{{ vars.controller_ip }}:6642
