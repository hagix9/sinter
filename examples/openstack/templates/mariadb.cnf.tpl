# Written by Sinter (hagistack: /etc/my.cnf.d/99-hagistack.cnf).
# Loopback only, on purpose: nothing outside this host opens the database. A compute node
# reaches the cell through nova-conductor, and compute credentials carry no database password.
[mysqld]
bind-address = 127.0.0.1
default-storage-engine = innodb
innodb_file_per_table = on
max_connections = {{ vars.mysql_max_connections }}
collation-server = utf8mb4_general_ci
character-set-server = utf8mb4
