# Written by Sinter (hagistack write_vhost). OpenStack 2026.1 removed the generated WSGI scripts, so
# mod_wsgi is pointed at the module (module and dir are relative to vars.py_site_packages).
Listen {{ template.port }}

<VirtualHost *:{{ template.port }}>
  WSGIDaemonProcess {{ template.name }} processes=3 threads=1 user={{ template.user }} group={{ template.user }} display-name=%{GROUP}
  WSGIProcessGroup {{ template.name }}
  WSGIScriptAlias / {{ vars.py_site_packages }}/{{ template.module }}
  WSGIApplicationGroup %{GLOBAL}
  WSGIPassAuthorization On
  LimitRequestBody 114688
  <Directory {{ vars.py_site_packages }}/{{ template.dir }}>
    Require all granted
  </Directory>
  ErrorLog /var/log/httpd/{{ template.name }}_error.log
  CustomLog /var/log/httpd/{{ template.name }}_access.log combined
</VirtualHost>
