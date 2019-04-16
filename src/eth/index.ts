/**
 * Ethereum Cold Storage
 */

 const util = require('ethereumjs-util');
 const Web3 = require("web3");
 const web3 = new Web3();

 

 export default class EthStorage{
     run(){
        const msg = 'hello world!';

      //   const account = web3.eth.accounts.create();
      //   const privateKey = account.privateKey;
      //   const address = account.address;

        const privateKey = '0x5fe128c58e43224a81ffecbc2166c3e05649b8103e66eae0124663cb2008b546'
        const address = '0x' + util.pubToAddress(util.privateToPublic(privateKey)).toString('hex');

        const sig = this.sign(msg, Buffer.from(privateKey.substr(2), 'hex'));
        const recover = this.recover(msg, sig);
        
        console.log(address, recover)
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
 }  

