# Written by Sinter.
[placement_database]
connection = mysql+pymysql://placement:{{ vars.placement_db_pass }}@127.0.0.1/placement?charset=utf8mb4
max_pool_size = {{ vars.db_max_pool_size }}
max_overflow = {{ vars.db_max_overflow }}
pool_timeout = 30

[api]
auth_strategy = keystone

[keystone_authtoken]
www_authenticate_uri = http://{{ vars.controller_ip }}:5000
auth_url = http://{{ vars.controller_ip }}:5000
memcached_servers = {{ vars.controller_ip }}:11211
auth_type = password
project_domain_name = Default
user_domain_name = Default
project_name = service
username = placement
password = {{ vars.placement_service_pass }}
