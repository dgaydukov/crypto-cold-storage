/**
 * Bitcoin Cold Storage
 */

 import {ECPair, payments} from 'bitcoinjs-lib';


 export default class Btctorage{
     run(){
        const keyPair = ECPair.fromPrivateKey(Buffer.from('12af1f8ebf88f3115f1c87195eab2e14d80b7ab92ba5626d5eadc989511009e7', 'hex'));
        const { address } = payments.p2pkh({ pubkey: keyPair.publicKey });
        console.log(address)
     } 
 }