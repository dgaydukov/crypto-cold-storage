/**
 * Different interfaces used accross the project
 */

export interface IWallet{
    privateKey: string;
    publicKey: string;
    address: string;
}

export interface IHDWallet{
    masterPrivateKey: string;
    masterPublicKey: string;
}

export interface IEthTxOpts{
    nonce: string
    gasPrice: string, 
    gasLimit: string,
    to: string, 
    value: string, 
    data: string,
    chainId: number,
}

export interface IBtcTxOpts{
}

export type ITxOpts = IEthTxOpts | IBtcTxOpts;

export interface ICryptoStorage{
    generateHdWallet(): IHDWallet;

    deriveWallet(index: string, masterPrivateKey: string): IWallet;

    generateWallet(): IWallet;

    getAddressFromPrivateKey(privateKey: string): string;

    getAddressFromPublicKey(publicKey: string): string;

    validateAddress(address: string): boolean;

    sign(msg: string, privateKey: string): string;

    verify(msg: string, sig: string, publicKey: string): boolean;

    recoverPublicKey(msg: string, sig: string): string;

    buildRawTx(opts: ITxOpts, privateKey: string): string;
}