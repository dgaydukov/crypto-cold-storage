/**
 * Bitcoin Cold Storage
 */

 import {ECPair, payments, networks, address as BitcoinAddress} from 'bitcoinjs-lib';
 const bip39 = require('bip39');
 const HDKey = require('hdkey');
 import {ICryptoStorage} from '../app/interfaces';


 export default class BtcStorage implements ICryptoStorage{

    constructor(){
        console.log(
            this.validateAddress('1MQrMtb91P333NPcvTsDkgE42ZqRQHzJPH')
        )
    }

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
        const wallet = this.generateWallet();
        return wallet;
    }
    
    generateWallet(){
        const wallet = ECPair.makeRandom();
        const { address } = payments.p2pkh({ pubkey: wallet.publicKey })
        return {
            privateKey: wallet.privateKey.toString('hex'),
            publicKey: wallet.publicKey.toString('hex'),
            address,
        }
    }

    getAddressFromPrivateKey(privateKey){
        const wallet = ECPair.fromPrivateKey(Buffer.from(privateKey, 'hex'));
        const { address } = payments.p2pkh({ pubkey: wallet.publicKey });
        return address;
     }
  
     getAddressFromPublicKey(publicKey){
        const { address } = payments.p2pkh({ pubkey: Buffer.from(publicKey, 'hex') });
        return address;
     }

     validateAddress(address){
         try{
            BitcoinAddress.toOutputScript(address);
            return true;
         }
         catch(ex){
             return false;
         }
     }

     sign(msg, privateKey){
         return '';
     }
  
     verify(msg, sig, publicKey){
         return false;
     }
  
     recoverPublicKey(msg, sig){
         return '';
     }
  
     buildRawTx(otps, privateKey){
        return '';
     }
 }