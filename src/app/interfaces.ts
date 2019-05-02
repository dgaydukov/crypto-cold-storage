import { SrvRecord } from "dns";

/**
 * Different interfaces used accross the project
 */

export interface IWallet {
    privateKey: string;
    publicKey: string;
    address: string;
}

export interface IHDWallet {
    masterPrivateKey: string;
    masterPublicKey: string;
}

export interface IEthTxOpts {
    nonce: string
    gasPrice: string,
    gasLimit: string,
    to: string,
    value: string,
    data: string,
    chainId: number,
}

export interface IUTXO {
    privateKey: string;
    address: string;
    value: string;
    txId: string;
    vout: number;
}

export interface ITarget {
    to: string;
    value: string;
}

export interface IBtcTxOpts {
    from: IUTXO[],
    to: ITarget[],
    changeAddress: string;
}

export interface EncryptedWallet {
    encryptedKey: string;
    address: string;
}

export type ITxOpts = IEthTxOpts | IBtcTxOpts;

export interface ICryptoStorage {
    generateHdWallet(): IHDWallet;

    deriveWallet(index: string, masterPrivateKey: string): IWallet;

    /**
     * If we set private key directly, we generate wallet based on this private key, 
     * otherwise we generate new random private key
     * 
     * @param privateKey {string}
     */
    generateWallet(privateKey?: string): IWallet;

    getAddressFromPrivateKey(privateKey: string): string;

    getAddressFromPublicKey(publicKey: string): string;

    getPublicKeyFromPrivateKey(privateKey: string): string;

    validateAddress(address: string): boolean;

    sign(msg: string, privateKey: string): string;

    verify(msg: string, sig: string, publicKey: string): boolean;

    hashMessage(msg: string): string;

    recoverPublicKey(msg: string, sig: string): string;

    buildRawTx(opts: ITxOpts, privateKey: string): string;


        
}