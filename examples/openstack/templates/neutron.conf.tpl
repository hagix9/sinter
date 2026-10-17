# Written by Sinter.
[DEFAULT]
core_plugin = ml2
service_plugins = ovn-router
auth_strategy = keystone
transport_url = rabbit://openstack:{{ vars.rabbit_pass }}@{{ vars.controller_ip }}:5672/

[database]
connection = mysql+pymysql://neutron:{{ vars.neutron_db_pass }}@127.0.0.1/neutron?charset=utf8mb4
max_pool_size = {{ vars.db_max_pool_size }}
max_overflow = {{ vars.db_max_overflow }}
pool_timeout = 30

[keystone_authtoken]
www_authenticate_uri = http://{{ vars.controller_ip }}:5000
auth_url = http://{{ vars.controller_ip }}:5000
memcached_servers = {{ vars.controller_ip }}:11211
auth_type = password
project_domain_name = Default
user_domain_name = Default
project_name = service
username = neutron
password = {{ vars.neutron_service_pass }}

# Neutron has to call Nova back when a port becomes ACTIVE, or every guest dies at vif_plugging_timeout.
[nova]
auth_url = http://{{ vars.controller_ip }}:5000/v3
auth_type = password
project_domain_name = Default
user_domain_name = Default
project_name = service
region_name = {{ vars.region_name }}
username = nova
password = {{ vars.nova_service_pass }}
