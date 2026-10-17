# Written by Sinter (OpenStack demo). Mode 0600, root only. Never commit.
# On a compute node only the five delivered credentials are set; the others are empty.
MYSQL_ROOT_PASS={{ vars.mysql_root_pass }}
KEYSTONE_DB_PASS={{ vars.keystone_db_pass }}
GLANCE_DB_PASS={{ vars.glance_db_pass }}
PLACEMENT_DB_PASS={{ vars.placement_db_pass }}
NEUTRON_DB_PASS={{ vars.neutron_db_pass }}
NOVA_DB_PASS={{ vars.nova_db_pass }}
RABBIT_PASS={{ vars.rabbit_pass }}
ADMIN_PASSWORD={{ vars.admin_password }}
GLANCE_SERVICE_PASS={{ vars.glance_service_pass }}
PLACEMENT_SERVICE_PASS={{ vars.placement_service_pass }}
NEUTRON_SERVICE_PASS={{ vars.neutron_service_pass }}
NOVA_SERVICE_PASS={{ vars.nova_service_pass }}
METADATA_PROXY_SECRET={{ vars.metadata_proxy_secret }}
HORIZON_SECRET_KEY={{ vars.horizon_secret_key }}
