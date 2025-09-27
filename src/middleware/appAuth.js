const User = require('../models/User');
const OpenSSLDecryption = require('../utils/opensslDecryption');
const logger = require('../utils/logger');

class AppAuthMiddleware {
    constructor() {
        this.decryption = new OpenSSLDecryption();
    }

    /**
     * Middleware para autenticação do app via campo 'e' criptografado
     */
    async authenticateApp(req, res, next) {
        try {
            const { action, t, e, ua } = req.query;
            
            // Verificar se é uma requisição de autenticação do app
            if (action !== 'auth' || !e) {
                return next(); // Passar para próximo middleware
            }

            logger.info(`🔐 Tentativa de autenticação do app - Action: ${action}, t: ${t}`);
            logger.info(`📱 User-Agent: ${ua || req.get('User-Agent') || 'Unknown'}`);
            logger.info(`🔒 Payload criptografado (primeiros 50 chars): ${e.substring(0, 50)}...`);

            // Processar payload criptografado
            const credentials = this.decryption.processEncryptedAuth(e);
            
            if (!credentials.username || !credentials.password) {
                logger.warn(`🚫 Credenciais não encontradas no payload`);
                return res.status(401).json({
                    success: false,
                    message: 'Credenciais não encontradas no payload',
                    error: 'INVALID_PAYLOAD'
                });
            }

            // Buscar usuário no banco
            const user = await User.findByUsername(credentials.username);
            
            if (!user) {
                logger.warn(`🔐 Usuário não encontrado: ${credentials.username}`);
                return res.status(401).json({
                    success: false,
                    message: 'Usuário não encontrado',
                    error: 'USER_NOT_FOUND'
                });
            }

            // Verificar senha
            const isValidPassword = await user.verifyPassword(credentials.password);
            
            if (!isValidPassword) {
                logger.warn(`🔐 Senha incorreta para usuário: ${credentials.username}`);
                return res.status(401).json({
                    success: false,
                    message: 'Credenciais inválidas',
                    error: 'INVALID_CREDENTIALS'
                });
            }

            // Verificar se usuário está válido (não expirado/suspenso)
            if (!user.isValid()) {
                logger.warn(`🔐 Usuário inválido: ${credentials.username} (Status: ${user.status})`);
                return res.status(403).json({
                    success: false,
                    message: user.status === 'expired' ? 'Usuário expirado' : 'Usuário suspenso',
                    error: 'USER_INVALID',
                    status: user.status
                });
            }

            // Atualizar último login
            await user.updateLastLogin();

            // Calcular dias restantes
            const now = new Date();
            const expiresAt = new Date(user.expires_at);
            const validityDays = Math.max(0, Math.ceil((expiresAt - now) / (1000 * 60 * 60 * 24)));

            // Resposta no formato esperado pelo app
            const authResponse = {
                success: true,
                username: user.username,
                password: 'authenticated', // Não retornar senha real
                validity_days: validityDays,
                message: 'Autenticado com sucesso',
                server: `http://${req.get('host')}`,
                ua: ua || req.get('User-Agent') || 'Xtream/2.0'
            };

            logger.info(`✅ Autenticação do app bem-sucedida - User: ${user.username}, Validade: ${validityDays} dias`);
            
            // Adicionar usuário ao request para uso posterior
            req.user = user;
            req.appAuth = true;
            req.deviceInfo = credentials.deviceInfo;

            return res.json(authResponse);

        } catch (error) {
            logger.error(`❌ Erro na autenticação do app: ${error.message}`);
            
            // Resposta de erro no formato esperado
            return res.status(500).json({
                success: false,
                message: 'Erro interno do servidor',
                error: 'INTERNAL_ERROR',
                details: process.env.NODE_ENV === 'development' ? error.message : undefined
            });
        }
    }

    /**
     * Middleware para outras ações do app (get_servers, etc.)
     */
    async handleAppActions(req, res, next) {
        try {
            const { action } = req.query;

            switch (action) {
                case 'get_servers':
                    return res.json([{
                        server_id: 1,
                        server_name: 'Main Server',
                        server_ip: req.get('host').split(':')[0],
                        server_port: req.get('host').split(':')[1] || '80',
                        status: 'Online',
                        load: 'Low'
                    }]);

                case 'get_account_info':
                    // Requer autenticação prévia
                    if (!req.user) {
                        return res.status(401).json({
                            success: false,
                            message: 'Autenticação necessária',
                            error: 'AUTH_REQUIRED'
                        });
                    }

                    const now = new Date();
                    const expiresAt = new Date(req.user.expires_at);
                    const validityDays = Math.max(0, Math.ceil((expiresAt - now) / (1000 * 60 * 60 * 24)));

                    return res.json({
                        success: true,
                        username: req.user.username,
                        validity_days: validityDays,
                        status: req.user.status,
                        user_type: req.user.user_type,
                        max_connections: req.user.max_connections,
                        expires_at: req.user.expires_at,
                        server: `http://${req.get('host')}`
                    });

                default:
                    // Passar para próximo middleware se não for ação conhecida
                    return next();
            }

        } catch (error) {
            logger.error(`❌ Erro ao processar ação do app: ${error.message}`);
            return res.status(500).json({
                success: false,
                message: 'Erro interno',
                error: 'INTERNAL_ERROR'
            });
        }
    }
}

module.exports = new AppAuthMiddleware();