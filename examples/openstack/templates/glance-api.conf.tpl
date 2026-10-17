# Written by Sinter.
[DEFAULT]
bind_host = {{ vars.mgmt_ip }}
bind_port = 9292

[database]
connection = mysql+pymysql://glance:{{ vars.glance_db_pass }}@127.0.0.1/glance?charset=utf8mb4
max_pool_size = {{ vars.db_max_pool_size }}
max_overflow = {{ vars.db_max_overflow }}
pool_timeout = 30

[glance_store]
stores = file
default_store = file
filesystem_store_datadir = /var/lib/glance/images/

[paste_deploy]
flavor = keystone

[keystone_authtoken]
www_authenticate_uri = http://{{ vars.controller_ip }}:5000
auth_url = http://{{ vars.controller_ip }}:5000
memcached_servers = {{ vars.controller_ip }}:11211
auth_type = password
project_domain_name = Default
user_domain_name = Default
project_name = service
username = glance
password = {{ vars.glance_service_pass }}
