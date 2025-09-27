const express = require('express');
const AuthMiddleware = require('../middleware/auth');
const AppAuthMiddleware = require('../middleware/appAuth');
const XtreamController = require('../controllers/XtreamController');

const router = express.Router();
const xtreamController = new XtreamController();

// Middleware de autenticação do app (para requisições com campo 'e')
router.use('/api.php', AppAuthMiddleware.authenticateApp);
router.use('/api.php', AppAuthMiddleware.handleAppActions);

// API alternativa (compatível com apps que usam criptografia)
router.get('/api.php', xtreamController.handleAlternativeAPI.bind(xtreamController));
router.post('/api.php', xtreamController.handleAlternativeAPI.bind(xtreamController));

// Aplicar autenticação tradicional nas demais rotas
router.use(AuthMiddleware.authenticateUser);

// API principal do Xtream
router.get('/player_api.php', xtreamController.handlePlayerAPI.bind(xtreamController));

// Rotas com prefixo /api/
router.get('/api/player_api.php', xtreamController.handlePlayerAPI.bind(xtreamController));

// Live TV streams
router.get('/live/:username/:password/:streamId.:extension', async (req, res) => {
    const { streamId, extension } = req.params;
    const stream = xtreamController.liveStreams.get(streamId);
    
    if (!stream) {
        return res.status(404).send('Canal não encontrado');
    }
    
    const originalUrl = `${process.env.ORIGINAL_API_URL}/${process.env.ORIGINAL_USERNAME}/${process.env.ORIGINAL_PASSWORD}/${streamId}.${extension}`;
    await xtreamController.proxyStream(originalUrl, req, res, req.user, stream.name);
});

router.get('/live/:username/:password/:streamId', async (req, res) => {
    req.params.extension = 'ts';
    const { streamId } = req.params;
    const stream = xtreamController.liveStreams.get(streamId);
    
    if (!stream) {
        return res.status(404).send('Canal não encontrado');
    }
    
    const originalUrl = `${process.env.ORIGINAL_API_URL}/${process.env.ORIGINAL_USERNAME}/${process.env.ORIGINAL_PASSWORD}/${streamId}.ts`;
    await xtreamController.proxyStream(originalUrl, req, res, req.user, stream.name);
});

// Movie streams
router.get('/movie/:username/:password/:streamId.:extension', async (req, res) => {
    const { streamId, extension } = req.params;
    const stream = xtreamController.vodStreams.get(streamId);
    
    if (!stream) {
        return res.status(404).send('Filme não encontrado');
    }
    
    const originalUrl = `${process.env.ORIGINAL_API_URL}/movie/${process.env.ORIGINAL_USERNAME}/${process.env.ORIGINAL_PASSWORD}/${streamId}.${extension}`;
    await xtreamController.proxyStream(originalUrl, req, res, req.user, stream.name);
});

router.get('/movie/:username/:password/:streamId', async (req, res) => {
    const { streamId } = req.params;
    const stream = xtreamController.vodStreams.get(streamId);
    
    if (!stream) {
        return res.status(404).send('Filme não encontrado');
    }
    
    const extension = stream.container_extension || 'mp4';
    const originalUrl = `${process.env.ORIGINAL_API_URL}/movie/${process.env.ORIGINAL_USERNAME}/${process.env.ORIGINAL_PASSWORD}/${streamId}.${extension}`;
    await xtreamController.proxyStream(originalUrl, req, res, req.user, stream.name);
});

// Series streams
router.get('/series/:username/:password/:seriesId/:seasonId/:episodeId.:extension', async (req, res) => {
    const { seriesId, seasonId, episodeId, extension } = req.params;
    const originalUrl = `${process.env.ORIGINAL_API_URL}/series/${process.env.ORIGINAL_USERNAME}/${process.env.ORIGINAL_PASSWORD}/${seriesId}/${seasonId}/${episodeId}.${extension}`;
    await xtreamController.proxyStream(originalUrl, req, res, req.user, `Serie_${seriesId}_S${seasonId}_E${episodeId}`);
});

router.get('/series/:username/:password/:episodeId.:extension', async (req, res) => {
    const { episodeId, extension } = req.params;
    const originalUrl = `${process.env.ORIGINAL_API_URL}/series/${process.env.ORIGINAL_USERNAME}/${process.env.ORIGINAL_PASSWORD}/${episodeId}.${extension}`;
    await xtreamController.proxyStream(originalUrl, req, res, req.user, `Episode_${episodeId}`);
});

// XMLtv
router.get('/xmltv.php', (req, res) => {
    res.setHeader('Content-Type', 'application/xml');
    res.send('<?xml version="1.0" encoding="UTF-8"?>\n<tv></tv>');
});

// Inicializar dados
xtreamController.loadFromXtreamAPI().then(() => {
    xtreamController.startAutoUpdate();
}).catch(err => {
    console.error('Erro ao carregar dados iniciais:', err.message);
});

module.exports = router;