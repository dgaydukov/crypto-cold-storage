/**
 * Ethereum Cold Storage
 * Basically we neeed only one library ethereumjs-util. That would be enough for everything
 * If we want to generate keys, we can use randomBytes from crypto library
 * To work with tx building we need ethereumjs-tx library
 * 
 * https://github.com/ethereumjs/ethereumjs-util - utils work with eth
 * https://github.com/ethereumjs/ethereumjs-tx - generate tx
 * https://github.com/ethereumjs/ethereumjs-wallet - for key encryption
 * https://github.com/cryptocoinjs/hdkey - use to generate hd wallet based on seed
 * https://github.com/bitcoinjs/bip39 - use to generate mnemonic seed
 * https://github.com/cryptocoinjs/secp256k1-node - not used directly here, but ethereumjs-util based on it
 */

const { randomBytes } = require('crypto');
const util = require('ethereumjs-util');
const EthereumTx = require('ethereumjs-tx');
const bip39 = require('bip39');
const HDKey = require('hdkey');
const Wallet = require('ethereumjs-wallet');
import { ICryptoStorage } from '../app/interfaces';
import Encryption from '../app/encryption';


export default class EthStorage implements ICryptoStorage {

   constructor(){
      //this.checkSign();

      const privateKey = 'a121f2bd62a5126dcd4ee357ec783b7678b262e545342ed4986aed7c47dd3129';
      const password = 'mysecurepassword';
      const encrypted = this.encryptWallet(privateKey, password);
      const decrypted = this.decryptWallet(encrypted, password);
      console.log(decrypted)
   }

   encryptWallet(privateKey, password){
      const key = Buffer.from(privateKey, 'hex');
      const wallet = Wallet.fromPrivateKey(key);
      return wallet.toV3String(password);
   }

   decryptWallet(wallet, password){
      return '';
   }


   encryptPK(privateKey, password){
       const address = this.getAddressFromPrivateKey(privateKey);
       const enc = new Encryption();
       const encryptedKey = enc.encrypt(privateKey, password);
       return {
           address,
           encryptedKey,
       };
   }

   decryptPK(wallet, password){
       const enc = new Encryption();
       const privateKey = enc.decrypt(wallet.encryptedKey, password);
       const address = this.getAddressFromPrivateKey(privateKey);
       if(address !== wallet.address){
           throw new Error(`Decrypted private key doesn't correspond to provided address. Your address: ${wallet.address}, decrypted address: ${address}`);
       }
       return privateKey;
   }

   checkSign(){
      /**
       * check this signing with geth
       * It was written, that geth use sha3 for hashing message before sign, but it turns out it use keccak
       * well, at least https://www.myetherwallet.com/ sign the same way
       * So need to check it out
       */
      const privateKey = 'a121f2bd62a5126dcd4ee357ec783b7678b262e545342ed4986aed7c47dd3129';
      const msg = 'hello world!';
      const publicKey = this.getPublicKeyFromPrivateKey(privateKey);
      const sig = this.sign(msg, privateKey);
      const verify = this.verify(msg, sig, publicKey);
      console.log(verify, sig);
   }

   generateHdWallet() {
      const mnemonic = bip39.generateMnemonic();
      const seed = bip39.mnemonicToSeedSync(mnemonic);
      const hdkey = HDKey.fromMasterSeed(seed);
      return {
         masterPrivateKey: hdkey.privateExtendedKey,
         masterPublicKey: hdkey.publicExtendedKey
      }
   }

   deriveWallet(index, masterPrivateKey) {
      const hdkey = HDKey.fromExtendedKey(masterPrivateKey);
      const path = `m/44'/60'/0'/0/${index}`;
      const child = hdkey.derive(path);
      return this.generateWallet(child.privateKey.toString('hex'));
   }

   generateWallet(privateKey?) {
      /**
       * It is adviced to check whether we generate correct private key or not here https://github.com/cryptocoinjs/secp256k1-node
       * But from my personal experience, I can say, that randomBytes always generate right key, moreover, privatekey - just a number
       * it can't be incorrect. But just in case...
       */
      if (privateKey) {
         privateKey = Buffer.from(privateKey, 'hex');
      }
      else {
         do {
            privateKey = randomBytes(32)
         } while (!util.isValidPrivate(privateKey));
      }

      const publicKey = util.privateToPublic(privateKey);
      const address = util.pubToAddress(publicKey);
      return {
         privateKey: privateKey.toString('hex'),
         publicKey: publicKey.toString('hex'),
         address: '0x' + address.toString('hex'),
      }
   }

   getAddressFromPrivateKey(privateKey) {
      const publicKey = util.privateToPublic(Buffer.from(privateKey, 'hex'));
      return this.getAddressFromPublicKey(publicKey);
   }

   getAddressFromPublicKey(publicKey) {
      const address = util.pubToAddress(Buffer.from(publicKey, 'hex'));
      return '0x' + address.toString('hex');
   }

   getPublicKeyFromPrivateKey(privateKey){
      const publicKey = util.privateToPublic(Buffer.from(privateKey, 'hex'));
      return publicKey.toString('hex');
   }

   validateAddress(address) {
      return util.isValidAddress(address);
   }

   sign(msg, privateKey) {
      const hash = this.hashMessage(msg);
      const sig = util.ecsign(hash, Buffer.from(privateKey, 'hex'));
      return '0x' + sig.r.toString('hex') + sig.s.toString('hex') + sig.v.toString(16);
   }

   verify(msg, sig, publicKey) {
      const recoveredPublicKey = this.recoverPublicKey(msg, sig);
      return recoveredPublicKey === publicKey;
   }

   hashMessage(msg: string){
      const message = Buffer.from(msg);
      const prefix = Buffer.from('\x19Ethereum Signed Message:\n' + message.length.toString())
      const finalMessage = Buffer.concat([prefix, message])
      const hash = util.keccak(finalMessage);
      return hash;
   }

   recoverPublicKey(msg, sig) {
      const r = Buffer.from(sig.substr(2, 64), 'hex');
      const s = Buffer.from(sig.substr(66, 64), 'hex');
      const v = Number('0x' + sig.substr(130, 2));
      const hash = this.hashMessage(msg);

      const publicKey = util.ecrecover(hash, v, r, s);
      return publicKey.toString('hex');
   }

   buildRawTx(opts, privateKey) {
      const tx = new EthereumTx(opts);
      tx.sign(privateKey);
      const serializedTx = tx.serialize();
      return serializedTx;
   }
}