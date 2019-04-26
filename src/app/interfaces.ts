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

    /**
     * Get address either from private or public key
     * @param key 
     */
    getAddressFromKey(key: string): string;

    validateAddress(address: string): boolean;

    sign(msg: string, key: string): string;

    verify(msg: string, hash: string): boolean;

    getAddressFromSignature(hash: string): string;

    getRawTx(txOptions: any): string;
}