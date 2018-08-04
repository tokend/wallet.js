var crypto = require('./util/crypto');
var sjcl = require('./util/sjcl');

var Keypair = require("tokend-js-base").Keypair;

var nacl = require('tweetnacl');

module.exports = {
  calculateWalletParams: calculateWalletParams,
  decryptKeychainData: decryptKeychainData,
  generateWalletData: generateWalletData,
  generateFactorData: generateFactorData,
  generateRecoveryData: generateRecoveryData
}

/**
 *
 * @param {string} password
 * @param {string} email
 * @param {string} salt
 * @param {object} kdfParams
 *
 * @returns {object} wallet
 */

function calculateWalletParams (password, email, salt, kdfParams) {
  var rawMasterKey = crypto.calculateMasterKey(salt, email, password, kdfParams);

  var rawWalletId = crypto.deriveWalletId(rawMasterKey);
  var rawWalletKey = crypto.deriveWalletKey(rawMasterKey);
  var walletId = sjcl.codec.hex.fromBits(rawWalletId);

  return { walletId: walletId, walletKey: rawWalletKey }
}

/**
 *
 * @param {string} keychainData
 * @param {ArrayBuffer} rawWalletKey
 *
 * @returns {object} rawKeychainData - account id and seed for current wallet
 */

function decryptKeychainData (keychainData, rawWalletKey) {
  return  JSON.parse(crypto.decryptData(keychainData, rawWalletKey));
}

/**
 *
 * @param {string} password
 * @param {string} email
 * @param {object} kdfParams
 * @param {string} rawKeychainData
 * @param {string} accountId
 *
 * @return {{id: *, attributes: {account_id: string, email: string, salt: string, keychain_data: string}}}
 */

function generateWalletData (password, email, kdfParams, rawKeychainData, accountId) {
  var salt = nacl.util.encodeBase64(nacl.randomBytes(16));

  var walletParams = calculateWalletParams(password, email, salt, kdfParams);
  var walletKey = walletParams.walletKey;
  var walletId = walletParams.walletId;

  var keychainData = crypto.encryptData(rawKeychainData, walletKey);

  return {
    id: walletId,
    attributes: {
      account_id: accountId,
      email: email,
      salt: salt,
      keychain_data: keychainData
    }
  };
}

/**
 *
 * @param {string} email
 * @param {string} password
 * @param {object} kdfParams
 *
 *  @return {{data: {type: string, id: *, attributes: {account_id: string, salt:string, keychain_data: string}}}}
 */

function generateFactorData (password, email, kdfParams) {
  var keypair = Keypair.random();
  var factorPublicKey = keypair.accountId();

  var factorSalt = nacl.util.encodeBase64(nacl.randomBytes(16));

  var factorWalletParams = calculateWalletParams(password, email, factorSalt, kdfParams);
  var factorWalletKey = factorWalletParams.walletKey;

  var rawTfaKeychainData = JSON.stringify({ seed: keypair.secret(), accountId: keypair.accountId() });
  var factorKeychainData = crypto.encryptData(rawTfaKeychainData, factorWalletKey);

  return {
    data: {
      type: 'password',
      attributes: {
        account_id: factorPublicKey,
        keychain_data: factorKeychainData,
        salt: factorSalt
      }
    }
  }
}

function generateRecoveryData (recoverySeed, email, kdfParams, rawKeychainData, accountId) {
  var recoverySalt = nacl.util.encodeBase64(nacl.randomBytes(16));

  var recoveryWalletParams = calculateWalletParams(recoverySeed, email, recoverySalt, kdfParams);
  var recoveryWalletId = recoveryWalletParams.walletId
  var recoveryWalletKey = recoveryWalletParams.walletKey;

  var recoveryKeychainData = crypto.encryptData(rawKeychainData, recoveryWalletKey);

  return {
    data: {
      type: 'password',
      id: recoveryWalletId,
      attributes: {
        account_id: accountId,
        keychain_data: recoveryKeychainData,
        salt: recoverySalt
      }
    }
  }
}
