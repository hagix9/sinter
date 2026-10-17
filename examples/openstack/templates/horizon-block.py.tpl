# >>> sinter-openstack begin — managed block, edit above this line
# Everything below is written by Sinter. The packaged settings above are left exactly as shipped; this file
# is Python and executes top to bottom, so these assignments win.
DEBUG = False
WEBROOT = '/dashboard/'
LOGIN_URL = WEBROOT + 'auth/login/'
LOGOUT_URL = WEBROOT + 'auth/logout/'
LOGIN_REDIRECT_URL = WEBROOT
ALLOWED_HOSTS = ['*']

OPENSTACK_HOST = "{{ vars.controller_ip }}"
OPENSTACK_KEYSTONE_URL = "http://{{ vars.controller_ip }}:5000/v3"
OPENSTACK_KEYSTONE_DEFAULT_ROLE = "member"
OPENSTACK_API_VERSIONS = {"identity": 3, "image": 2, "volume": 3}
OPENSTACK_KEYSTONE_MULTIDOMAIN_SUPPORT = False
OPENSTACK_KEYSTONE_DEFAULT_DOMAIN = "Default"

SECRET_KEY = "{{ vars.horizon_secret_key }}"

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.memcached.PyMemcacheCache',
        'LOCATION': '{{ vars.controller_ip }}:11211',
    },
}
SESSION_ENGINE = 'django.contrib.sessions.backends.cache'

# This cloud has no Cinder and no Swift.
OPENSTACK_NEUTRON_NETWORK = {
    'enable_router': True,
    'enable_quotas': True,
    'enable_ipv6': False,
    'enable_distributed_router': False,
    'enable_ha_router': False,
    'enable_fip_topology_check': False,
}
# <<< sinter-openstack end
