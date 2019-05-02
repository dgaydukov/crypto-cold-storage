/**
 * Bitcoin Cold Storage
 */

import { ECPair, payments, TransactionBuilder, address as BitcoinAddress } from 'bitcoinjs-lib';
const bip39 = require('bip39');
const HDKey = require('hdkey');
const secp256k1 = require('secp256k1')
const coinSelect = require('coinselect');
import { ICryptoStorage } from '../app/interfaces';
const bip38 = require('bip38');
const wif = require('wif');
import Encryption from '../app/encryption';


export default class BtcStorage implements ICryptoStorage {

    constructor() {
        //this.checkSign();

        const privateKey = 'a121f2bd62a5126dcd4ee357ec783b7678b262e545342ed4986aed7c47dd3129';
        const password = 'password';

        const encrypted = this.encryptWallet(privateKey, password);
        const decrypted = this.decryptWallet(encrypted, password);
        console.log(decrypted)
    }

    encryptWallet(privateKey, password){
        const address = this.getAddressFromPrivateKey(privateKey);
        const wallet = ECPair.fromPrivateKey(Buffer.from(privateKey, 'hex'));
        const privateKeyWif = wallet.toWIF();
        const decoded = wif.decode(privateKeyWif);
        const encryptedKey = bip38.encrypt(decoded.privateKey, decoded.compressed, password)
        return {
            address,
            encryptedKey,
        };
    }

    decryptWallet(wallet, password){
        const encryptedKey = wallet.encryptedKey;
        const decryptedKey = bip38.decrypt(encryptedKey, password, (status) => {
            // will print the percent every time current increases by 1000
            // console.log(status.percent) 
        });
        const privateKeyWif = wif.encode(0x80, decryptedKey.privateKey, decryptedKey.compressed);
        const keyPair = ECPair.fromWIF(privateKeyWif);
        const privateKey = keyPair.privateKey.toString('hex');
        const address = this.getAddressFromPrivateKey(privateKey);
        if(wallet.address !== address){
            throw new Error(`Decrypted private key doesn't correspond to provided address. Your address: ${wallet.address}, decrypted address: ${address}`);
        }
        return privateKey;
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

    checkSign() {
        /**
         * check signage with bitcoin-cli, to be sure we correctly sign message
         */
        const privateKey = 'a121f2bd62a5126dcd4ee357ec783b7678b262e545342ed4986aed7c47dd3129';
        const msg = 'hello world!';
        const publicKey = this.getPublicKeyFromPrivateKey(privateKey);

        const sig = this.sign(msg, privateKey);
        const check = this.verify(msg, sig, publicKey);
        console.log(check, sig)
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

    getPublicKeyFromPrivateKey(privateKey) {
        const wallet = ECPair.fromPrivateKey(Buffer.from(privateKey, 'hex'));
        return wallet.publicKey.toString('hex');
    }

    sign(msg, privateKey) {
        const messageHash = this.hashMessage(msg);
        const sigObj = secp256k1.sign(Buffer.from(messageHash, 'hex'), Buffer.from(privateKey, 'hex'));
        const sig = sigObj.signature.toString('base64');
        return sig;
    }

    verify(msg, sig, publicKey) {
        const messageHash = this.hashMessage(msg);
        return secp256k1.verify(Buffer.from(messageHash, 'hex'), Buffer.from(sig, 'base64'), Buffer.from(publicKey, 'hex'));;
    }

    hashMessage(msg) {
        const prefixMsgBuffer = Buffer.from('Bitcoin Signed Message:\n');
        const messageBuffer = Buffer.from(msg);
        const prefix1 = Buffer.from(prefixMsgBuffer.length.toString());
        const prefix2 = Buffer.from(messageBuffer.length.toString());
        const buffer = Buffer.concat([prefix1, prefixMsgBuffer, prefix2, messageBuffer]);
        return this.doublesha256(buffer);
    }

    doublesha256(msg){
        const enc = new Encryption();
        return enc.sha256(enc.sha256(msg));
    }

    recoverPublicKey(msg, sig) {
        return '';
    }

    buildRawTx(opts, baseFeeRate) {
        opts.from.map((key, i) => {
            tx.addInput("", 1);
        });

        const { inputs, outputs, fee } = coinSelect(opts.from, opts.to, baseFeeRate);

        // the accumulated fee is always returned for analysis
        console.log(`total fee is: ${fee}`);

        // .inputs and .outputs will be undefined if no solution was found
        if (!inputs || !outputs) return

        let tx = new TransactionBuilder()

        inputs.forEach((input, i) => {
            tx.addInput(input.txId, input.vout);
            tx.sign(i, input.privateKey);
        });
        outputs.forEach(output => {
            // watch out, outputs may have been added that you need to provide
            // an output address/script for
            if (!output.address) {
                output.address = opts.changeAddress;
            }
            tx.addOutput(output.address, output.value);
        })

        return tx.build().toHex();
    }
}