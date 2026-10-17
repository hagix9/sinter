# Written by Sinter.
[ml2]
type_drivers = flat,vlan,geneve
tenant_network_types = geneve
mechanism_drivers = ovn
extension_drivers = port_security
overlay_ip_version = 4

[ml2_type_geneve]
vni_ranges = 1:65536
max_header_size = 38

[ml2_type_flat]
flat_networks = {{ vars.provider_physnet }}

[ml2_type_vlan]
network_vlan_ranges = {{ vars.provider_physnet }}

[securitygroup]
enable_security_group = true

[ovn]
ovn_nb_connection = tcp:127.0.0.1:6641
ovn_sb_connection = tcp:{{ vars.controller_ip }}:6642
ovn_l3_scheduler = leastloaded
ovn_metadata_enabled = true
