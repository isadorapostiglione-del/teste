const crypto = require('crypto');

// Classe para testar a autenticação do app
class AppAuthTester {
    constructor() {
        this.passphrase = 'jb%!SZfM%AwwS7JmdM!';
    }

    // Implementa EVP_BytesToKey igual ao OpenSSL
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

    // Criptografar payload como o app faz
    encryptPayload(plaintext) {
        // 1. Gerar salt aleatório (8 bytes)
        const salt = crypto.randomBytes(8);
        
        // 2. Derivar key e iv
        const { key, iv } = this.evpBytesToKey(this.passphrase, salt);
        
        // 3. Criptografar com AES-256-CBC
        const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
        let encrypted = cipher.update(plaintext, 'utf8');
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        
        // 4. Montar formato OpenSSL: "Salted__" + salt + ciphertext
        const saltedPrefix = Buffer.from('Salted__', 'utf8');
        const result = Buffer.concat([saltedPrefix, salt, encrypted]);
        
        // 5. Base64 encode e URL encode
        const base64 = result.toString('base64');
        const urlEncoded = encodeURIComponent(base64);
        
        return urlEncoded;
    }

    // Gerar payload de teste
    generateTestPayload(username, password) {
        const payload = `wifi=${username}:${password}&lan=${username}:${password}&code=NAN&mobile=NAN&isMobile=false`;
        return this.encryptPayload(payload);
    }

    // Testar com diferentes usuários
    async testAuthentication() {
        console.log('🧪 Testando autenticação do app...\n');

        const testCases = [
            { username: 'ABC1234', password: 'test123' },
            { username: 'XYZ5678', password: 'password456' },
            { username: 'ADMIN001', password: 'admin123456' }
        ];

        for (const testCase of testCases) {
            console.log(`📱 Testando: ${testCase.username}:${testCase.password}`);
            
            const encryptedPayload = this.generateTestPayload(testCase.username, testCase.password);
            console.log(`🔒 Payload criptografado: ${encryptedPayload.substring(0, 100)}...`);
            
            const testUrl = `http://localhost:3000/api.php?action=auth&t=7&e=${encryptedPayload}`;
            console.log(`🌐 URL de teste: ${testUrl.substring(0, 150)}...\n`);
            
            // Aqui você pode fazer a requisição HTTP real se quiser
            // const response = await fetch(testUrl);
            // console.log('Resposta:', await response.json());
        }

        console.log('✅ Payloads de teste gerados!');
        console.log('\n📋 Para testar manualmente:');
        console.log('1. Inicie o servidor: npm start');
        console.log('2. Use as URLs geradas acima em um cliente HTTP');
        console.log('3. Verifique os logs do servidor para debug');
    }
}

// Executar teste
const tester = new AppAuthTester();
tester.testAuthentication().catch(console.error);