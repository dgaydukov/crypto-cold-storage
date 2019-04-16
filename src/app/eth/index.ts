/**
 * Ethereum Cold Storage
 */

 const util = require('ethereumjs-util');
 const Web3 = require("web3");
 const web3 = new Web3();

 

 export default class EthStorage{
     run(){
        const msg = 'hello world!';
        const account = web3.eth.accounts.create();

        // const privateKey = account.privateKey;
        // const address = account.address;

        const privateKey = '0x5fe128c58e43224a81ffecbc2166c3e05649b8103e66eae0124663cb2008b546'
        const address = util.pubToAddress(util.privateToPublic(privateKey)).toString('hex');

        const sig = this.sign(msg, Buffer.from(privateKey.substr(2), 'hex'));
        const recover = this.recover(msg, sig);

        const recover2 = this.recover2(msg, '0x28d21d33bd0fb358cbc1a13541c5b5a3bc1e134adc7c43ce011dd704029c322a21cfc9b742b336aaecc598ee331a43e87ea33d68e937be04f870b7f52cbf0a2e1c');
        console.log(address, recover, recover2);
     } 

     sign(msg: string, privateKey: Buffer): string{
        const hash = util.sha256(msg);
        const sig = util.ecsign(hash, privateKey);
        return '0x' + sig.r.toString('hex') + sig.s.toString('hex') + sig.v.toString(16).toString();
     } 

     recover(msg: string, sig: string){
        const r = Buffer.from(sig.substr(2, 64), 'hex');
        const s = Buffer.from(sig.substr(66, 64), 'hex');
        const v = Number('0x' + sig.substr(130, 2));
        const hash = util.sha256(msg);
        
        const publicKey = util.ecrecover(hash, v, r, s);
        const address = '0x' + util.pubToAddress(publicKey).toString('hex');
        return address;
     }

     recover2(msg: string, sig: string){
        const r = Buffer.from(sig.substr(2, 64), 'hex');
        const s = Buffer.from(sig.substr(66, 64), 'hex');
        const v = Number('0x' + sig.substr(130, 2));

        const prefix = util.toBuffer("\x19Ethereum Signed Message:\n");
        const _msg = util.toBuffer(msg);
        const prefixedMsg = util.sha256(
            Buffer.concat([prefix, util.toBuffer(String(_msg.length)), _msg])
        );
        
        const publicKey = util.ecrecover(prefixedMsg, v, r, s);
        const address = '0x' + util.pubToAddress(publicKey).toString('hex');
        return address;
     }
 }  

