#!/bin/bash node

// Packages in use in the program
// express - for creating the server
// crypto - for encrypting and decrypting data
// uuid - for generating UUIDs

const express = require('express');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

const app = express();
const port = process.env.PORT || 3000;

app.get('/encrypt', async (req, res) => {    
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

    res.status(200).json({ encrypted: encryptedData, decrypted: decryptedData });
});

app.listen(port, () => {
    console.log(`Example app listening at http://localhost:${port}`);
});
