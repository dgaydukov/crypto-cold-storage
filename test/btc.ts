import { assert } from 'chai';
import BtcStorage from '../src/btc/index';

describe('Bitcoin test', ()=>{
    const storage = new BtcStorage();
    it('Should generate hd wallet', ()=>{
        const wallet = storage.generateHdWallet();
        assert.equal(wallet.masterPrivateKey.length, 111, 'Length of masterPrivateKey should be 111');
        assert.equal(wallet.masterPublicKey.length, 111, 'Length of masterPublicKey should be 111');
    });

    it('Should derive correct wallet', ()=>{
        const masterPrivateKey = 'xprv9s21ZrQH143K3DqMhsxsHa6T8DYYXEr8EQti8Hamw5ArLaaXoCiYkYfKLARwHEu5HaAMqCejdQqgAoLZ9haN55cnLrNcp5XDZXKWUYVJfNQ';
        const index = '123';
        const derivedPrivateKey = '6a13202e1c7d39b9df8a8a5bebe839d6e96cf8aa45be772da14d4d55f35b5a72';
        const wallet = storage.deriveWallet(index, masterPrivateKey);
        assert.equal(wallet.privateKey, derivedPrivateKey, `Private keys don't match`)
    });

    it('Should generate keypair', ()=>{
        const wallet = storage.generateWallet();
        assert.equal(wallet.privateKey.length, 64, `Private key has incorrect length`);
        assert.equal(wallet.publicKey.length, 66, `Public key has incorrect length`);
        assert.equal(wallet.address.length, 34, `Address has incorrect length`);
    });

    it('Should derive correct address from private key', ()=>{
        const privateKey = '6a13202e1c7d39b9df8a8a5bebe839d6e96cf8aa45be772da14d4d55f35b5a72';
        const derivedAddress = '18ZeRaVweF77B31wEK7VqTHkH7G6YErggM';
        const address = storage.getAddressFromPrivateKey(privateKey);
        assert.equal(address, derivedAddress, `Addresses don't match`);
    });

    it('Should derive correct address from public key', ()=>{
        const publicKey = '02f4a5a5338a30996ade173df27a186bbfdb5284bbeb1b1296d85ae787adbb118e';
        const derivedAddress = '1vFDTtG9d878scEFnEbP6nQ5ECVabEjgC';
        const address = storage.getAddressFromPublicKey(publicKey);
        assert.equal(address, derivedAddress, `Addresses don't match`);
    });

    it('Should validate address', ()=>{
        const address1 = '1vFDTtG9d878scEFnEbP6nQ5ECVabEjgC';
        const address2 = '1vFDTtG9d878scEFnEbP6nQ5ECVabEjg2';
        const valid1 = storage.validateAddress(address1);
        assert.isTrue(valid1, 'First address is correct address');
        const valid2 = storage.validateAddress(address2);
        assert.isFalse(valid2, 'Second address is incorrect address');
    });

    it('Should sing/verify message', ()=>{
        const privateKey = '4d76783eb3d17813387fd60fe8f9435166536f960e0fd56657b61dfac80afcda';
        const publicKey = '024b13825112ab196b1cbed76d37c6176a58bbcded5defb3f9da949ebadc46f5e7';
        const msg = 'Hello World!!!';
        const sig = 'nN/se7hKWBQKMyeA8EjDtHIpGPboGjaeKNY/ocsOY1US9KhSDEqyeNEDDvrQd5ZdpIXiOOpuEmrmv2gOEUKa+Q==';
        const newSig = storage.sign(msg, privateKey);
        assert.equal(newSig, sig, `Signatures don't match`);
        const verify = storage.verify(msg, sig, publicKey);
        assert.isTrue(verify, 'Verification should return true');
    });
});