# Admin credentials for the openstack client (Sinter OpenStack demo) — do not commit.
export OS_AUTH_URL=http://{{ vars.controller_ip }}:5000/v3
export OS_IDENTITY_API_VERSION=3
export OS_PROJECT_DOMAIN_NAME=Default
export OS_USER_DOMAIN_NAME=Default
export OS_PROJECT_NAME=admin
export OS_USERNAME=admin
export OS_PASSWORD={{ vars.admin_password }}
export OS_REGION_NAME={{ vars.region_name }}
