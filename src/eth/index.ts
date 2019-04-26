/**
 * Ethereum Cold Storage
 * Basically we neeed only one library ethereumjs-util. That would be enough for everything
 * If we want to generate keys, we can use randomBytes from crypto library
 * To work with tx building we need ethereumjs-tx library
 * 
 * https://github.com/ethereumjs/ethereumjs-util
 * https://github.com/ethereumjs/ethereumjs-tx
 * https://github.com/cryptocoinjs/secp256k1-node
 */

const { randomBytes } = require('crypto');
const util = require('ethereumjs-util');
const EthereumTx = require('ethereumjs-tx')
const bip39 = require('bip39');
const HDKey = require('hdkey')
import {ICryptoStorage} from '../app/interfaces';
 

 export default class EthStorage implements ICryptoStorage{

   generateHdWallet(){
      const mnemonic = bip39.generateMnemonic();
      const seed = bip39.mnemonicToSeedSync(mnemonic);
      const hdkey = HDKey.fromMasterSeed(seed);
      return {
         masterPrivateKey: hdkey.privateExtendedKey,
         masterPublicKey: hdkey.publicExtendedKey
      }
   }

   deriveWallet(index, masterPrivateKey){
      const hdkey = HDKey.fromExtendedKey(masterPrivateKey);
      const path = `m/44'/60'/0'/0/${index}`;
      const child = hdkey.derive(path);
      const privateKey = child.privateKey;
      const publicKey = util.privateToPublic(child.privateKey);
      const address = util.pubToAddress(publicKey);
      const keyPair = {
         privateKey: privateKey.toString('hex'),
         publicKey: publicKey.toString('hex'),
         address: '0x' + address.toString('hex'),
      };
      return keyPair;
   }

   generateWallet(){
      /**
       * It is adviced to check whether we generate correct private key or not here https://github.com/cryptocoinjs/secp256k1-node
       * But from my personal experience, I can say, that randomBytes always generate right key, moreover, privatekey - just a number
       * it can't be incorrect. But just in case...
       */
      let privateKey;
      do {
         privateKey = randomBytes(32)
      } while (!util.isValidPrivate(privateKey));

      const publicKey = util.privateToPublic(privateKey);
      const address = util.pubToAddress(publicKey);
      const keyPair = {
         privateKey: privateKey.toString('hex'),
         publicKey: publicKey.toString('hex'),
         address: '0x' + address.toString('hex'),
      }

      return keyPair;
   }

   getAddressFromPrivateKey(privateKey){
      const publicKey = util.privateToPublic(Buffer.from(privateKey, 'hex'));
      const address = util.pubToAddress(publicKey);
      return '0x' + address.toString('hex');
   }

   getAddressFromPublicKey(publicKey){
      const address = util.pubToAddress(Buffer.from(publicKey, 'hex'));
      return '0x' + address.toString('hex');
   }

   validateAddress(address){
      return util.isValidAddress(address);
   }

   sign(msg, privateKey){
      const hash = util.sha256(msg);
      const sig = util.ecsign(hash, Buffer.from(privateKey, 'hex'));
      return '0x' + sig.r.toString('hex') + sig.s.toString('hex') + sig.v.toString(16);
   }

   verify(msg, sig, publicKey){
      const recoveredPublicKey = this.recoverPublicKey(msg, sig);
      return recoveredPublicKey === publicKey;
   }

   recoverPublicKey(msg, sig){
      const r = Buffer.from(sig.substr(2, 64), 'hex');
      const s = Buffer.from(sig.substr(66, 64), 'hex');
      const v = Number('0x' + sig.substr(130, 2));
      const hash = util.sha256(msg);
      
      const publicKey = util.ecrecover(hash, v, r, s);
      return publicKey.toString('hex');
   }

   buildRawTx(otps, privateKey){
      const tx = new EthereumTx(otps);
      tx.sign(privateKey);
      const serializedTx = tx.serialize();
      return serializedTx;
   }
 }  

