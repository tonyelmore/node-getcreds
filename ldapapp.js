#!/bin/bash node

const express = require('express');
const ldap = require('ldapjs');

const app = express();
app.use(express.json());
const port = process.env.PORT || 3000;

const hardcodedEmail = 'tonyelmore@example.org';
const developersGroupDN = 'cn=developers, dc=example, dc=org';
const userSearchDN = 'dc=example,dc=org';
const adminDN = 'cn=admin,dc=example,dc=org';
const adminPassword = 'admin';
const ldapUrl = 'ldap://localhost:389';

app.get('/ldap', (req, res, next) => {
    const client = ldap.createClient({ url: ldapUrl });

    client.bind(adminDN, adminPassword, (err) => {
        if (err) {
            return res.status(500).json({ message: 'LDAP bind failed', error: err });
        }

        const searchFilter = `(mail=${hardcodedEmail})`;
        const searchOptions = {
            filter: searchFilter,
            scope: 'sub',
            attributes: ['dn', 'cn'],   // Retrieve distinguished name and common name
        };

        client.search(userSearchDN, searchOptions, (err, result) => {
            if (err) {
                return res.status(500).json({ message: 'LDAP Search Failed', error: err });
            }

            let userDN = null;

            result.on('searchEntry', (entry) => {
                userDN = entry.object.dn;
            });

            result.on('end', () => {
                if (!userDN) {
                    client.unbind();
                    return res.status(403).json({ message: 'User not found' });
                }

                const groupFilter = `(member=${userDN})`;
                const groupSearchOptions = {
                    filter: groupFilter,
                    scope: 'sub',
                    attributes: ['cn']   // We only care if the group entry exists
                };

                client.search(developersGroupDN, groupSearchOptions, (err, groupResult) => {
                    if (err) {
                        client.unbind();
                        return res.status(500).json({ message: 'LDAP Group Search Failed', error: err });
                    }

                    let isMember = false;
                    groupResult.on('searchEntry', () => {
                        isMember = true;    // If we find the user in the group
                    });

                    groupResult.on('end', () => {
                        client.unbind();  // Close the connection
                    
                        if (isMember) {
                                return res.status(200).json({ message: 'User is in the group', hardcodedEmail });
                        } else {
                                return res.status(403).json({ message: 'User is not in the group', hardcodedEmail });
                        }
                    });
                });
            });
        });
    });
});

app.listen(port, () => {
    console.log(`Example app listening at http://localhost:${port}`);
});
