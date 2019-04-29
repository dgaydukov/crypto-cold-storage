import { assert } from 'chai';
import EthStorage from '../src/eth/index';

describe('Ethereum test', ()=>{
    const storage = new EthStorage();
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
        assert.equal(wallet.publicKey.length, 128, `Public key has incorrect length`);
        assert.equal(wallet.address.length, 42, `Address has incorrect length`);
    });

    it('Should derive correct address from private key', ()=>{
        const privateKey = '6a13202e1c7d39b9df8a8a5bebe839d6e96cf8aa45be772da14d4d55f35b5a72';
        const derivedAddress = '0x50acaf08f3244241648b597ae1fc3918493c1db1';
        const address = storage.getAddressFromPrivateKey(privateKey);
        assert.equal(address, derivedAddress, `Addresses don't match`);
    });

    it('Should derive correct address from public key', ()=>{
        const publicKey = '29b796ba9688009bd27066440c71decee0bbc0906a0873d401bd443ca158b292f5ab562971229906087875b6f574921fb70c50129783bb25ee6f9e9aa50bccc4';
        const derivedAddress = '0x0d619255c76c24232bf19326bc4883e16ae9f09f';
        const address = storage.getAddressFromPublicKey(publicKey);
        assert.equal(address, derivedAddress, `Addresses don't match`);
    });

    it('Should validate address', ()=>{
        const address1 = '0x6b71386ef1de32ab89867eb0a05ddd48f9283d64';
        const address2 = '0x6b71386ef1de32ab89867eb0a05ddd48f9283d6';
        const valid1 = storage.validateAddress(address1);
        assert.isTrue(valid1, 'First address is correct address');
        const valid2 = storage.validateAddress(address2);
        assert.isFalse(valid2, 'Second address is incorrect address');
    });

    it('Should sing/verify message', ()=>{
        const privateKey = 'f85a5d9edc3cadba7be545fbb02692aaf4c12cb553dc026edd6158dc766fe752';
        const publicKey = 'f553ecc0c8541f39c8d7da94db3be7605c64e1864b0c5a3ff56db836607576d252bad6efeed6ffd03fb20da286ec3f7938642c07d61cf9b65b340683d26da861';
        const msg = 'Hello World!!!';
        const sig = '0x0b8aa9c4e9c6973b7a45c9d0c4ec39da52049879be128e05efd43f6d84e27dfa56ec075e25f012804398ee6620d7077b814f153efe860ec7588351b45c2ed0e61c';
        const newSig = storage.sign(msg, privateKey);
        assert.equal(newSig, sig, `Signatures don't match`);
        const verify = storage.verify(msg, sig, publicKey);
        assert.isTrue(verify, 'Verification should return true');
    });
});