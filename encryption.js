//1. Encrypt data (Symmetric)
console.log("An Initialization Vector (IV) is a random or pseudorandom value used to initialize a cryptographic algorithm or mode to ensure uniqueness in encryption, preventing patterns in the encrypted data that could be exploited by attackers.")

//Determining if crypto support is unavailable
let crypto;
try {
    crypto = require('node:crypto');
} catch (err) {
    console.error('crypto support is disabled!');
}

//Variables
let iv;
let cypher;
let encrypted;

//function taking the string 'secret' and a string 'key' as input and returning a cypher of the input
// string using an Initialisation Vector and AES 256 algorithm
function encryptdata(secret, key) {
    //generates a random 16-byte IV used to initialize the encryption algorithm and ensure that each encryption is unique,
    // even when encrypting the same data with the same key
    iv = crypto.randomBytes(16)
    //creates a new cipher object 'cypher' that will be used to encrypt data using the AES 256 algorithm with cbc mode,
    //the encryption key 'key' and the 'iv' buffer as the IV
    cypher = crypto.createCipheriv('aes-256-cbc', key, iv);
    //let's encrypt the string 'secret' using 'cypher'.
    //update() : encrupt the data and returns a buffer
    //final() : performs final encryption steps
    encrypted = Buffer.concat([cypher.update(secret), cypher.final()])
    //returns a string that contains the hexadecimal string representation
    //of the encrypted data
    console.log("IV : ")
    console.log(`${iv.toString('hex')}`)
    console.log("Encrypted message : ")
    return `${encrypted.toString('hex')}`
}

console.log("\n Let's encrypt 'alisonlyesilv' ! \n")
let key = crypto.createHash('sha256').update(String('alisonlyesilv')).digest('base64').substr(0, 32);
const bytes = new TextEncoder().encode(key).length
console.log("Bytes : ", bytes)
console.log(encryptdata('alisonlyesilv', key))
console.log("Key : ", key)

//2. Decrypt data (Symmetric)

let decipher;
let decrypted;

function decryptdata(ciphertext, key) {
    decipher = crypto.createDecipheriv('aes-256-cbc', key, Buffer.from(iv, 'hex'));
    decrypted = Buffer.concat([decipher.update(Buffer.from(ciphertext, 'hex')), decipher.final()]);
    return decrypted.toString();
}

console.log("\n Let's decrypt the received message ! \n")
console.log("Decrypted message : ")
console.log(decryptdata(encrypted, key))

//4. Asymmetric encryption

console.log(" \n Let's generate a public/private RSA key pair ! \n")

// Generate a new RSA key pair
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
    },
    privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
    }
});

console.log('Public key:\n', publicKey);
console.log('Private key:\n', privateKey);

//Encryption
let buffer;
let encryptedMessage;
function encryptWithPublicKey(message, publicKey) {
    //The butter.from method is used to convert the plaintext 'message'
    // to a Buffer object using the utf-8 encoding
    buffer = Buffer.from(message, 'utf-8');
    //The publicEncrypt method is used to encrypt the message
    // with the given publicKey in PEM format
    encryptedMessage = crypto.publicEncrypt(publicKey, buffer);
    //The encrypted data is converted to a Base64-encoded string
    return encrypted.toString('base64');
}
console.log("Encryption : ")
console.log(encryptWithPublicKey("Bienvenue à tous !", publicKey))

//Decryption
function decryptWithPrivateKey(encryptedMessage, privateKey) {
    const buffer = Buffer.from(encryptedMessage, 'base64');
    //The privateDecrypt method is used to decrypt the message with the given privateKey in PEM format
    const decrypted = crypto.privateDecrypt({ key: privateKey, passphrase: '' }, buffer);
    return decrypted.toString('utf-8');
}
console.log("Decryption : ")
console.log(decryptWithPrivateKey(encryptedMessage, privateKey))