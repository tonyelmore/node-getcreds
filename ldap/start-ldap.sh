docker network create ldap-network

docker run --name ldap-service \
    --network ldap-network \
    -p 389:389 \
    -p 636:636 \
    --env LDAP_ORGANISATION="ExampleOrg" \
    --env LDAP_DOMAIN="example.org" \
    --env LDAP_ADMIN_PASSWORD="admin" \
    -d osixia/openldap:1.5.0 

docker run --name phpldapadmin \
    --network ldap-network \
    -p 443:443 \
    --env PHPLDAPADMIN_LDAP_HOSTS=ldap-service \
    -d osixia/phpldapadmin

