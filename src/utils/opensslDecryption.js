const crypto = require('crypto');
const logger = require('./logger');

class OpenSSLDecryption {
    constructor() {
        // Passphrase embutida no cliente (conforme especificado)
        this.passphrase = 'jb%!SZfM%AwwS7JmdM!';
    }

    /**
     * Implementa EVP_BytesToKey do OpenSSL usando MD5
     * Deriva key (32 bytes) e iv (16 bytes) para AES-256-CBC
     */
    evpBytesToKey(password, salt, keyLen = 32, ivLen = 16) {
        const targetLen = keyLen + ivLen;
        const derived = Buffer.alloc(targetLen);
        let derivedLen = 0;
        let prevHash = Buffer.alloc(0);

        while (derivedLen < targetLen) {
            const hash = crypto.createHash('md5');
            hash.update(prevHash);
            hash.update(password, 'utf8');
            hash.update(salt);
            prevHash = hash.digest();

            const copyLen = Math.min(prevHash.length, targetLen - derivedLen);
            prevHash.copy(derived, derivedLen, 0, copyLen);
            derivedLen += copyLen;
        }

        return {
            key: derived.slice(0, keyLen),
            iv: derived.slice(keyLen, keyLen + ivLen)
        };
    }

    /**
     * Descriptografa payload no formato OpenSSL "Salted__"
     */
    decryptPayload(encryptedData) {
        try {
            // 1. URL decode se necessário
            let urlDecoded = decodeURIComponent(encryptedData);
            
            // 2. Base64 decode
            const binaryData = Buffer.from(urlDecoded, 'base64');
            
            // 3. Verificar prefixo "Salted__"
            const saltedPrefix = Buffer.from('Salted__', 'utf8');
            if (!binaryData.slice(0, 8).equals(saltedPrefix)) {
                throw new Error('Formato inválido: prefixo "Salted__" não encontrado');
            }

            // 4. Extrair salt (8 bytes após "Salted__")
            const salt = binaryData.slice(8, 16);
            
            // 5. Extrair ciphertext
            const ciphertext = binaryData.slice(16);

            // 6. Derivar key e iv usando EVP_BytesToKey
            const { key, iv } = this.evpBytesToKey(this.passphrase, salt);

            // 7. Descriptografar com AES-256-CBC
            const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
            let decrypted = decipher.update(ciphertext);
            decrypted = Buffer.concat([decrypted, decipher.final()]);

            const plaintext = decrypted.toString('utf8');
            
            logger.info(`🔓 Payload descriptografado: ${plaintext}`);
            
            return plaintext;

        } catch (error) {
            logger.error(`❌ Erro na descriptografia: ${error.message}`);
            throw new Error(`Falha na descriptografia: ${error.message}`);
        }
    }

    /**
     * Parse do payload descriptografado (formato key=value&key2=value2)
     */
    parsePayload(plaintext) {
        const params = {};
        const pairs = plaintext.split('&');
        
        for (const pair of pairs) {
            const [key, value] = pair.split('=');
            if (key && value !== undefined) {
                params[key] = decodeURIComponent(value);
            }
        }
        
        return params;
    }

    /**
     * Extrair credenciais do payload parseado
     */
    extractCredentials(params) {
        let username = null;
        let password = null;

        // Tentar extrair de 'wifi' primeiro, depois 'lan'
        const wifiData = params.wifi || params.lan;
        
        if (wifiData && wifiData.includes(':')) {
            const [user, pass] = wifiData.split(':', 2);
            username = user;
            password = pass;
        }

        return {
            username,
            password,
            deviceInfo: {
                code: params.code || 'NAN',
                mobile: params.mobile || 'NAN',
                isMobile: params.isMobile === 'true'
            }
        };
    }

    /**
     * Processo completo de descriptografia e extração
     */
    processEncryptedAuth(encryptedData) {
        try {
            // 1. Descriptografar
            const plaintext = this.decryptPayload(encryptedData);
            
            // 2. Parse do payload
            const params = this.parsePayload(plaintext);
            
            // 3. Extrair credenciais
            const credentials = this.extractCredentials(params);
            
            logger.info(`🔐 Credenciais extraídas - User: ${credentials.username}, Device: ${JSON.stringify(credentials.deviceInfo)}`);
            
            return credentials;

        } catch (error) {
            logger.error(`❌ Erro no processamento da autenticação: ${error.message}`);
            throw error;
        }
    }
}

module.exports = OpenSSLDecryption;