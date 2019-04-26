/**
 * Different interfaces used accross the project
 */

export interface IKeyPair{
    privateKey: string;
    publicKey: string;
    address: string;
}

export interface ICryptoStorage{
    generateKeyPair(): IKeyPair;

    getAddressFromPrivateKey(privateKey: string): string;

    getAddressFromPublicKey(publicKey: string): string;

    validateAddress(address: string): boolean;

    sign(msg: string, privateKey: string): string;

    verify(msg: string, sig: string, publicKey: string): boolean;

    recoverPublicKey(msg: string, sig: string): string;
}