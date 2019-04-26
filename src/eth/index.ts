/**
 * Ethereum Cold Storage
 */

const util = require('ethereumjs-util');
const { randomBytes } = require('crypto');
import {ICryptoStorage} from '../app/interfaces';
 

 export default class EthStorage implements ICryptoStorage{

   generateKeyPair(){
      const privateKey = randomBytes(32);
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
 }  

