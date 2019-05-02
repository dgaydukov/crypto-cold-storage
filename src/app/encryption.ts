const crypto = require('crypto');

const ENCRYPTION_ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const AUTHTAG_LENGTH = 16;

export default class Encryption{

    sha256(msg) {
        return crypto.createHash('sha256').update(msg).digest('hex');
    }

    encrypt(msg: string, password: string){
        const iv = crypto.randomBytes(IV_LENGTH);
        const key = Buffer.from(this.sha256(password), 'hex');
        const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, key, iv, { authTagLength: AUTHTAG_LENGTH});
        let encrypted = cipher.update(msg, 'utf8');
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        const final = Buffer.concat([iv, encrypted, cipher.getAuthTag()]);
        return final.toString('hex');
    }

    decrypt(encrypted: string, password: string){
        const encryptedBuf = Buffer.from(encrypted, 'hex');
        const authTag = encryptedBuf.slice(-AUTHTAG_LENGTH);
        const iv = encryptedBuf.slice(0, IV_LENGTH);
        const encryptedMessage = encryptedBuf.slice(IV_LENGTH, -AUTHTAG_LENGTH);
        const key = Buffer.from(this.sha256(password), 'hex');
        const decipher = crypto.createDecipheriv(ENCRYPTION_ALGORITHM, key, iv, { authTagLength: AUTHTAG_LENGTH});
        decipher.setAuthTag(authTag);
        let messagetext = decipher.update(encryptedMessage);
        messagetext = Buffer.concat([messagetext, decipher.final()]);
        return messagetext.toString('utf8');
    }
}