#!/bin/bash node

// Packages in use in the program
// dotenv - for reading environment variables from .env file
// ldapjs - for interacting with LDAP server
// express - for creating the server
// crypto - for encrypting and decrypting data
// jwt - for decoding JWT tokens
// uuid - for generating UUIDs

require('dotenv').config();

const express = require('express');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const https = require('https');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const ldap = require('ldapjs');

const app = express();
const port = process.env.PORT || 3000;

const systemDomain = process.env.SYSTEM_DOMAIN;

const vcapServices = JSON.parse(process.env.VCAP_SERVICES);
const credhubCredentials = vcapServices.credhub[0].credentials;
const mySecret = credhubCredentials.keyone;

//LDAP
//const hardcodedEmail = 'tonyelmore@example.org';
const developersGroupDN = 'cn=developers, dc=example, dc=org';
const userSearchDN = 'dc=example,dc=org';
const adminDN = 'cn=admin,dc=example,dc=org';
const adminPassword = 'admin';
const ldapUrl = 'ldap://localhost:389';
// End LDAP

const agent = new https.Agent({
    rejectUnauthorized: false,
});

app.get('/', async (req, res) => {    

    // ##### Encrypt and Decrypt Data #####

    // Step 1: Generate a UUID
    const uuid = uuidv4();
    console.log('UUID', uuid);

    // Step 2: Derive an encryption key from the UUID
    // Note: AES requires either a 16, 24, or 32-byte key
    const key = crypto.createHash('sha256').update(uuid).digest('base64').substr(0, 32);

    // Step 3: Define encryption parameters
    const algorithm = 'aes-256-cbc';
    const iv = crypto.randomBytes(16);  // Initialization vector
    const cipher = crypto.createCipheriv(algorithm, Buffer.from(key), iv);

    // Step 4: Encrypt some data
    const data = 'LDAP_Group';
    let encryptedData = cipher.update(data, 'utf8', 'hex');
    encryptedData += cipher.final('hex');
    
    console.log('Encrypted Data: ', encryptedData);
    console.log('Intialization Vector: ', iv.toString('hex'));

    // Now - let's decrypt the data
    const d_key = crypto.createHash('sha256').update(uuid).digest('base64').substr(0, 32);
    const d_iv = Buffer.from(iv.toString('hex'), 'hex');
    const d_algorithm = 'aes-256-cbc';
    const decipher = crypto.createDecipheriv(d_algorithm, Buffer.from(d_key), d_iv);
    let decryptedData = decipher.update(encryptedData, 'hex', 'utf8');
    decryptedData += decipher.final('utf8');

    console.log('Decrypted Data: ', decryptedData);

    // #### End Encrypt and Decrypt Data ####



    // Back to our normally scheduled programming
    const wftoken = req.headers['wftoken'];
    if (!wftoken) {
        return res.status(400).send('No token provided, only got $req.headers');
    }
    
    // Decode the JWT token and get the userID
    try {
        // Don't even treally need to get the userid from the token because the call to uaa userinfo takes in the token 
        // and returns the user email field
        // Decode the JWT token to extract user_id
        const decodedToken = jwt.decode(wftoken);
        if (!decodedToken || !decodedToken.user_id) {
            return res.status(400).json({ error: 'Invalid token or user_id not found'});
        }

        // const userID = decodedToken.user_id;
        // console.log('userID extracted from token: ', userID);




        // #### Get UserId by curl to uaa ####
        const userInfoUrl = `https://uaa.sys.${systemDomain}.h2o.vmware.com/userinfo`;
        console.log("userurl: ", userInfoUrl);
        console.log("token: ", wftoken);
        const userInfoResponse = await axios.get(userInfoUrl, {
            headers: {
                Authorization: `bearer ${wftoken}`
            },
            httpsAgent: agent,
        });

        console.log("Return from call", userInfoResponse.data);
        let userID = userInfoResponse.data.email;
        console.log('User name: ', userID);


        // Test - should have "admin"
        // Test - change to hardcoded value just to hit LDAP correctly
        userID = 'tonyelmore@example.org';





        // #### Find user in LDAP ####
        // Using the user_id extracted from the token, check if that user is in LDAP
        // and if they belong to the correct group.
        const client = ldap.createClient({ url: ldapUrl });

        client.bind(adminDN, adminPassword, (err) => {
            if (err) {
                return res.status(500).json({ message: 'LDAP bind failed', error: err });
            }
            const searchFilter = `(mail=${userID})`;
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
                                    return res.status(200).json({ message: 'User is in the group - return the ssh key', userID });
                            } else {
                                    return res.status(403).json({ message: 'User is not in the group - do not return the ssh key', userID });
                            }
                        });
                    });
                });
            });
        });
        // #### End LDAP ####


        // res.status(500).json({ result: 'Unknown error - should not have gotten this far' });
        // res.send(`${mySecret}`);

    } catch (error) {
        if (error.response) {
            console.error('Error Response Data', error.response.data);
            console.error('Error Status: ', error.response.status);
            console.error('Error Headers:', error.response.headers);
        } else {
            console.error('Error:', error.message);
        }
        res.status(500).json({ error: 'An error occured while processing the request' });
    }

});





app.get('/test', (req, res) => {
    let credentials;

    if (process.env.VCAP_SERVICES) {
        const vcapServices = JSON.parse(process.env.VCAP_SERVICES);
        if (vcapServices.credhub) {
            credentials = vcapServices.credhub[0].credentials;
        }
    } else {
        res.send('VCAP_SERVICES not found');
    }

    if (credentials) {
        res.send(`Hello NODE World! ${credentials.keyone}`);
    } else {
        res.send('Credentials not found');
    }
});

app.listen(port, () => {
    console.log(`Example app listening at http://localhost:${port}`);
});
