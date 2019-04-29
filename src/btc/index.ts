/**
 * Bitcoin Cold Storage
 */

import { ECPair, payments, TransactionBuilder, address as BitcoinAddress } from 'bitcoinjs-lib';
const bip39 = require('bip39');
const HDKey = require('hdkey');
import { ICryptoStorage } from '../app/interfaces';

var bitcore = require('bitcore-lib');
var Message = require('bitcore-message');

export default class BtcStorage implements ICryptoStorage {

    constructor() {
    //   const privateKey = 'a121f2bd62a5126dcd4ee357ec783b7678b262e545342ed4986aed7c47dd3129';
    //   const publicKey = this.getPublicKeyFromPrivateKey(privateKey);
      
    //   var privateKey = bitcore.PrivateKey.fromWIF('cPBn5A4ikZvBTQ8D7NnvHZYCAxzDZ5Z2TSGW2LkyPiLxqYaJPBW4');
    //   var signature = Message('hello, world').sign(privateKey);
    //   console.log(signature)
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
        let wallet;
        if (privateKey) {
            wallet = ECPair.fromPrivateKey(Buffer.from(privateKey, 'hex'));
        }
        else {
            wallet = ECPair.makeRandom();
        }
        const { address } = payments.p2pkh({ pubkey: wallet.publicKey })
        return {
            privateKey: wallet.privateKey.toString('hex'),
            publicKey: wallet.publicKey.toString('hex'),
            address,
        }
    }

    getAddressFromPrivateKey(privateKey) {
        const wallet = ECPair.fromPrivateKey(Buffer.from(privateKey, 'hex'));
        const { address } = payments.p2pkh({ pubkey: wallet.publicKey });
        return address;
    }

    getAddressFromPublicKey(publicKey) {
        const { address } = payments.p2pkh({ pubkey: Buffer.from(publicKey, 'hex') });
        return address;
    }

    validateAddress(address) {
        try {
            BitcoinAddress.toOutputScript(address);
            return true;
        }
        catch (ex) {
            return false;
        }
    }

    getPublicKeyFromPrivateKey(privateKey){
       const wallet = ECPair.fromPrivateKey(Buffer.from(privateKey, 'hex'));
       return wallet.publicKey.toString('hex');
    }

    sign(msg, privateKey) {
        return '';
    }

    verify(msg, sig, publicKey) {
        return false;
    }

    hashMessage(msg){
        return '';
    }

    recoverPublicKey(msg, sig) {
        return '';
    }

    buildRawTx(opts, privateKey) {
        const tx = new TransactionBuilder();
        opts.from.map((key, i) => {
            tx.addInput("", 1);
            tx.sign(i, key)
        });
        for (const to of opts.to) {
            tx.addOutput(to.address, to.value);
        }
        return tx.build().toHex();
    }
}