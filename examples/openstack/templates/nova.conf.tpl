# Written by Sinter. One template for the controller, the all-in-one node and a compute-only node.
# The variable nova_db_prefix is empty where the cell database is opened (controller, all-in-one) and
# "# " on a compute-only node, which must not open it: nova-compute reaches the cell through
# nova-conductor (hagistack comments the keys out for the same reason).
[DEFAULT]
host = {{ vars.os_hostname }}
my_ip = {{ vars.mgmt_ip }}
transport_url = rabbit://openstack:{{ vars.rabbit_pass }}@{{ vars.controller_ip }}:5672/
# Without state_path nova derives it from its installation directory and cannot write compute_id.
state_path = /var/lib/nova
# EL ships no nova-compute.conf; without this nova-compute exits: "Compute driver option required".
compute_driver = libvirt.LibvirtDriver

[service_user]
auth_url = http://{{ vars.controller_ip }}:5000/v3
auth_type = password
project_domain_name = Default
user_domain_name = Default
project_name = service
region_name = {{ vars.region_name }}
username = nova
password = {{ vars.nova_service_pass }}
send_service_user_token = true

[placement]
auth_url = http://{{ vars.controller_ip }}:5000/v3
auth_type = password
project_domain_name = Default
user_domain_name = Default
project_name = service
region_name = {{ vars.region_name }}
username = placement
password = {{ vars.placement_service_pass }}
valid_interfaces = internal

[neutron]
auth_url = http://{{ vars.controller_ip }}:5000/v3
auth_type = password
project_domain_name = Default
user_domain_name = Default
project_name = service
region_name = {{ vars.region_name }}
username = neutron
password = {{ vars.neutron_service_pass }}
valid_interfaces = internal
service_metadata_proxy = true
metadata_proxy_shared_secret = {{ vars.metadata_proxy_secret }}

[glance]
valid_interfaces = internal

[vnc]
enabled = true
server_listen = {{ vars.mgmt_ip }}
server_proxyclient_address = {{ vars.mgmt_ip }}

[oslo_concurrency]
lock_path = /var/lib/nova/tmp

[os_vif_ovs]
ovsdb_connection = tcp:127.0.0.1:6640

[libvirt]
virt_type = {{ vars.virt_type }}
{{ vars.libvirt_cpu_mode_line }}

[keystone_authtoken]
www_authenticate_uri = http://{{ vars.controller_ip }}:5000
auth_url = http://{{ vars.controller_ip }}:5000
memcached_servers = {{ vars.controller_ip }}:11211
auth_type = password
project_domain_name = Default
user_domain_name = Default
project_name = service
username = nova
password = {{ vars.nova_service_pass }}

[api_database]
{{ vars.nova_db_prefix }}connection = mysql+pymysql://nova:{{ vars.nova_db_pass }}@127.0.0.1/nova_api?charset=utf8mb4
{{ vars.nova_db_prefix }}max_pool_size = {{ vars.db_max_pool_size }}
{{ vars.nova_db_prefix }}max_overflow = {{ vars.db_max_overflow }}
{{ vars.nova_db_prefix }}pool_timeout = 30

[database]
{{ vars.nova_db_prefix }}connection = mysql+pymysql://nova:{{ vars.nova_db_pass }}@127.0.0.1/nova?charset=utf8mb4
{{ vars.nova_db_prefix }}max_pool_size = {{ vars.db_max_pool_size }}
{{ vars.nova_db_prefix }}max_overflow = {{ vars.db_max_overflow }}
{{ vars.nova_db_prefix }}pool_timeout = 30

[scheduler]
# A later compute node still has to be mapped into a cell; do it on a timer.
{{ vars.nova_db_prefix }}discover_hosts_in_cells_interval = 300
