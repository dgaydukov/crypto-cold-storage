/**
 * Bitcoin Cold Storage
 */

import { ECPair, payments, TransactionBuilder, address as BitcoinAddress } from 'bitcoinjs-lib';
const bip39 = require('bip39');
const HDKey = require('hdkey');
const secp256k1 = require('secp256k1')
const { createHash } = require('crypto');
const coinSelect = require('coinselect');
import { ICryptoStorage } from '../app/interfaces';


const crypto = require('crypto');

export default class BtcStorage implements ICryptoStorage {

    constructor() {
        const algorithm = 'aes-256-gcm';
        
        const encrypt = (msg: string, password: string) => {
            const iv = crypto.randomBytes(16);
            const key = Buffer.from(this.sha256(password), 'hex');
            const cipher = crypto.createCipheriv(algorithm, key, iv, { authTagLength: 16});
            let encrypted = cipher.update(msg, 'utf8');
            encrypted = Buffer.concat([encrypted, cipher.final()]);
            const final = Buffer.concat([iv, encrypted, cipher.getAuthTag()]);
            return final.toString('hex');
        }
        
        const decrypt = (encrypted: string, password: string) => {
            const encryptedBuf = Buffer.from(encrypted, 'hex');
            const authTag = encryptedBuf.slice(-16);
            const iv = encryptedBuf.slice(0, 16);
            const encryptedMessage = encryptedBuf.slice(16, -16);
            const key = Buffer.from(this.sha256(password), 'hex');
            const decipher = crypto.createDecipheriv(algorithm, key, iv, { authTagLength: 16});
            decipher.setAuthTag(authTag);
            let messagetext = decipher.update(encryptedMessage);
            messagetext = Buffer.concat([messagetext, decipher.final()]);
            return messagetext.toString('utf8');
        }

        const privateKey = 'a121f2bd62a5126dcd4ee357ec783b7678b262e545342ed4986aed7c47dd3129';
        const password = 'mysecurepassword';
        const encrypted = encrypt(privateKey, password);
        console.log(encrypted);
        const decrypted = decrypt(encrypted, password);
        console.log(decrypted);

        //this.checkSign(); 
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
        return this.sha256(this.sha256(buffer));
    }


    sha256(msg) {
        return createHash('sha256').update(msg).digest('hex');
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