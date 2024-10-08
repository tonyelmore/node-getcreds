docker cp user.ldif ldap-service:/user.ldif
docker exec -i ldap-service ldapadd -x -D "cn=admin,dc=example,dc=org" -w admin -f /user.ldif

docker cp johndoe.ldif ldap-service:/johndoe.ldif
docker exec -i ldap-service ldapadd -x -D "cn=admin,dc=example,dc=org" -w admin -f /johndoe.ldif
