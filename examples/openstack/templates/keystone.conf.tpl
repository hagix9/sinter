# Written by Sinter. The EL packaging ships no /etc/keystone/keystone.conf at all.
[database]
connection = mysql+pymysql://keystone:{{ vars.keystone_db_pass }}@127.0.0.1/keystone?charset=utf8mb4
max_pool_size = {{ vars.db_max_pool_size }}
max_overflow = {{ vars.db_max_overflow }}
pool_timeout = 30

[token]
provider = fernet

[cache]
backend = oslo_cache.memcache_pool
enabled = true
memcache_servers = {{ vars.controller_ip }}:11211
