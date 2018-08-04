'use strict';

var _ = require('lodash');
var errors = require('./errors');
var sjcl = require('./sjcl');

module.exports = {
    calculateMasterKey: calculateMasterKey,
    decryptData: decryptData,
    deriveWalletId: generateDeriveFromKeyFunction('WALLET_ID'),
    deriveWalletKey: generateDeriveFromKeyFunction('WALLET_KEY'),
    encryptData: encryptData
};

function base64Encode(str) {
    return (new Buffer(str)).toString('base64');
}

function base64Decode(str) {
    return (new Buffer(str, 'base64')).toString();
}

function generateDeriveFromKeyFunction(token) {
    return function(masterKey) {
        var hmac = new sjcl.misc.hmac(masterKey, sjcl.hash.sha256);
        return hmac.encrypt(token);
    };
}

function encryptData(data, key) {
    if (!_.isString(data)) {
        throw new TypeError('data must be a String.');
    }

    var cipherName = 'aes';
    var modeName = 'gcm';

    var cipher = new sjcl.cipher[cipherName](key);
    var rawIV = sjcl.random.randomWords(3);
    var encryptedData = sjcl.mode[modeName].encrypt(
        cipher,
        sjcl.codec.utf8String.toBits(data),
        rawIV
    );

    data = JSON.stringify({
        IV: sjcl.codec.base64.fromBits(rawIV),
        cipherText: sjcl.codec.base64.fromBits(encryptedData),
        cipherName: cipherName,
        modeName: modeName
    });

    return base64Encode(data);
}

function decryptData(encryptedData, key) {
    var rawCipherText, rawIV, cipherName, modeName;
    try {
        var resultObject = JSON.parse(base64Decode(encryptedData));
        rawIV = sjcl.codec.base64.toBits(resultObject.IV);
        rawCipherText = sjcl.codec.base64.toBits(resultObject.cipherText);
        cipherName = resultObject.cipherName;
        modeName = resultObject.modeName;
    } catch (e) {
        new errors.DataCorrupt();
    }
    var cipher = new sjcl.cipher[cipherName](key);
    var rawData = sjcl.mode[modeName].decrypt(cipher, rawCipherText, rawIV);
    return sjcl.codec.utf8String.fromBits(rawData);
}

function calculateMasterKey(s0, username, password, kdfParams) {
    var versionBits = sjcl.codec.hex.toBits("0x01");
    var s0Bits = sjcl.codec.base64.toBits(s0);
    var usernameBits = sjcl.codec.utf8String.toBits(username);
    var unhashedSaltBits = _.reduce([versionBits, s0Bits, usernameBits], sjcl.bitArray.concat);
    var salt = sjcl.hash.sha256.hash(unhashedSaltBits);

    return sjcl.misc.scrypt(
        password,
        salt,
        kdfParams.n,
        kdfParams.r,
        kdfParams.p,
        kdfParams.bits / 8
    );
}
