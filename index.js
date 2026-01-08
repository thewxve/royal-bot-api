/**
 * ═══════════════════════════════════════════════════════════════
 * ROYAL NOTIFIER - LICENSE API
 * API de licenciamento com proteções de segurança
 * ═══════════════════════════════════════════════════════════════
 */

import express from 'express';
import mongoose from 'mongoose';
import rateLimit from 'express-rate-limit';
import crypto from 'crypto';
import 'dotenv/config';

const app = express();
app.use(express.json());

// Trust proxy para obter IP real (Render, Railway, etc)
app.set('trust proxy', 1);

// ═══════════════════════════════════════════════════════════════
// RATE LIMITING - Proteção contra brute force
// ═══════════════════════════════════════════════════════════════

// Rate limit global (50 requisições por 15 minutos por IP)
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 50,
    message: { success: false, message: 'Muitas requisições. Tente novamente mais tarde.' },
    standardHeaders: false,
    legacyHeaders: false,
    keyGenerator: (req) => req.ip
});

// Rate limit estrito para ativação (5 tentativas por minuto por IP)
const activationLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 5,
    message: { success: false, message: 'Limite de tentativas excedido. Aguarde 1 minuto.' },
    standardHeaders: false,
    legacyHeaders: false,
    keyGenerator: (req) => req.ip
});

app.use(globalLimiter);

// ═══════════════════════════════════════════════════════════════
// MONGODB CONNECTION
// ═══════════════════════════════════════════════════════════════

const MONGO_URI = process.env.MONGO_URI;

mongoose.connect(MONGO_URI).then(() => {
    console.log('[DB] ✅ Conectado ao MongoDB');
}).catch(err => {
    console.error('[DB] ❌ Erro de conexão:', err.message);
    process.exit(1);
});

// ═══════════════════════════════════════════════════════════════
// KEY SCHEMA
// ═══════════════════════════════════════════════════════════════

const keySchema = new mongoose.Schema({
    key: {
        type: String,
        required: true,
        unique: true,
        index: true
    },
    plan: {
        type: String,
        enum: ['24h', '7d', '30d', 'lifetime'],
        required: true
    },
    duration: {
        type: Number,
        default: null // null para lifetime
    },
    activatedAt: {
        type: Date,
        default: null
    },
    expiresAt: {
        type: Date,
        default: null
    },
    hwid: {
        type: String,
        default: null
    },
    active: {
        type: Boolean,
        default: false
    },
    attempts: {
        type: Number,
        default: 0
    },
    blockedUntil: {
        type: Date,
        default: null
    }
});

const Key = mongoose.model('Key', keySchema);

// ═══════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════

// Prefixos válidos de keys
const VALID_PREFIXES = ['RP-H24', 'RP-D07', 'RP-D30', 'RP-LFT'];

// Validar formato da key
function isValidKeyFormat(key) {
    if (!key || typeof key !== 'string') return false;

    // Formato: RP-XXX-XXXXXXXX
    const keyUpper = key.toUpperCase().trim();
    const prefix = keyUpper.substring(0, 6);

    if (!VALID_PREFIXES.includes(prefix)) return false;
    if (keyUpper.length < 14) return false;

    return true;
}

// Verificar se key está bloqueada temporariamente
function isKeyBlocked(keyDoc) {
    if (!keyDoc.blockedUntil) return false;
    return new Date() < new Date(keyDoc.blockedUntil);
}

// Verificar se key está expirada
function isKeyExpired(keyDoc) {
    if (keyDoc.plan === 'lifetime') return false;
    if (!keyDoc.expiresAt) return false;
    return new Date() > new Date(keyDoc.expiresAt);
}

// Calcular tempo restante
function getTimeRemaining(keyDoc) {
    if (keyDoc.plan === 'lifetime') {
        return { unlimited: true, text: 'Vitalício' };
    }

    if (!keyDoc.expiresAt) return { expired: true, text: 'Não ativada' };

    const now = new Date();
    const expires = new Date(keyDoc.expiresAt);
    const diff = expires - now;

    if (diff <= 0) {
        return { expired: true, text: 'Expirada' };
    }

    const hours = Math.floor(diff / (1000 * 60 * 60));
    const days = Math.floor(hours / 24);

    if (days > 0) {
        return { days, hours: hours % 24, text: `${days}d ${hours % 24}h restantes` };
    }

    return { hours, text: `${hours}h restantes` };
}

// ═══════════════════════════════════════════════════════════════
// ENDPOINTS
// ═══════════════════════════════════════════════════════════════

/**
 * POST /activate
 * Ativar ou validar uma key
 * Body: { key: string, hwid: string }
 */
app.post('/activate', activationLimiter, async (req, res) => {
    try {
        const { key, hwid } = req.body;

        // ─────────────────────────────────────────────────────────
        // Validação de input
        // ─────────────────────────────────────────────────────────
        if (!key || !hwid) {
            return res.json({
                success: false,
                message: 'Dados incompletos'
            });
        }

        if (typeof key !== 'string' || typeof hwid !== 'string') {
            return res.json({
                success: false,
                message: 'Formato inválido'
            });
        }

        const keyUpper = key.toUpperCase().trim();
        const hwidTrim = hwid.trim();

        // Validar formato da key
        if (!isValidKeyFormat(keyUpper)) {
            return res.json({
                success: false,
                message: 'Chave inválida'
            });
        }

        // Validar HWID
        if (hwidTrim.length < 32) {
            return res.json({
                success: false,
                message: 'Identificador inválido'
            });
        }

        // ─────────────────────────────────────────────────────────
        // Buscar key no banco
        // ─────────────────────────────────────────────────────────
        const keyDoc = await Key.findOne({ key: keyUpper });

        if (!keyDoc) {
            return res.json({
                success: false,
                message: 'Chave não encontrada'
            });
        }

        // ─────────────────────────────────────────────────────────
        // Verificar se está bloqueada temporariamente
        // ─────────────────────────────────────────────────────────
        if (isKeyBlocked(keyDoc)) {
            const waitTime = Math.ceil((new Date(keyDoc.blockedUntil) - new Date()) / 1000 / 60);
            return res.json({
                success: false,
                message: `Chave bloqueada temporariamente. Tente novamente em ${waitTime} minutos.`
            });
        }

        // ─────────────────────────────────────────────────────────
        // KEY AINDA NÃO ATIVADA - Primeira ativação
        // ─────────────────────────────────────────────────────────
        if (!keyDoc.active && !keyDoc.hwid) {
            const now = new Date();

            // Calcular expiração
            let expiresAt = null;
            if (keyDoc.plan !== 'lifetime' && keyDoc.duration) {
                expiresAt = new Date(now.getTime() + (keyDoc.duration * 1000));
            }

            // Atualizar key
            keyDoc.active = true;
            keyDoc.activatedAt = now;
            keyDoc.expiresAt = expiresAt;
            keyDoc.hwid = hwidTrim;
            keyDoc.attempts = 0;

            await keyDoc.save();

            const timeInfo = getTimeRemaining(keyDoc);

            return res.json({
                success: true,
                message: 'Licença ativada com sucesso!',
                plan: keyDoc.plan,
                expiresAt: keyDoc.expiresAt,
                timeRemaining: timeInfo.text,
                firstActivation: true
            });
        }

        // ─────────────────────────────────────────────────────────
        // KEY JÁ ATIVADA - Validação de retorno
        // ─────────────────────────────────────────────────────────

        // Verificar HWID
        if (keyDoc.hwid !== hwidTrim) {
            // Incrementar tentativas falhas
            keyDoc.attempts = (keyDoc.attempts || 0) + 1;

            // Bloquear após 5 tentativas com HWID errado
            if (keyDoc.attempts >= 5) {
                keyDoc.blockedUntil = new Date(Date.now() + 30 * 60 * 1000); // 30 min
                await keyDoc.save();

                return res.json({
                    success: false,
                    message: 'Chave bloqueada por tentativas excessivas. Aguarde 30 minutos.'
                });
            }

            await keyDoc.save();

            return res.json({
                success: false,
                message: 'Esta licença está vinculada a outra máquina'
            });
        }

        // Verificar expiração
        if (isKeyExpired(keyDoc)) {
            return res.json({
                success: false,
                message: 'Licença expirada',
                expired: true
            });
        }

        // Resetar tentativas em caso de sucesso
        if (keyDoc.attempts > 0) {
            keyDoc.attempts = 0;
            await keyDoc.save();
        }

        const timeInfo = getTimeRemaining(keyDoc);

        return res.json({
            success: true,
            message: 'Licença válida',
            plan: keyDoc.plan,
            expiresAt: keyDoc.expiresAt,
            timeRemaining: timeInfo.text,
            firstActivation: false
        });

    } catch (error) {
        console.error('[API] Erro:', error.message);
        return res.json({
            success: false,
            message: 'Erro interno do servidor'
        });
    }
});

/**
 * POST /validate
 * Validação rápida (sem logs, para verificação periódica)
 * Body: { key: string, hwid: string }
 */
app.post('/validate', async (req, res) => {
    try {
        const { key, hwid } = req.body;

        if (!key || !hwid) {
            return res.json({ valid: false });
        }

        const keyDoc = await Key.findOne({
            key: key.toUpperCase().trim(),
            hwid: hwid.trim(),
            active: true
        });

        if (!keyDoc) {
            return res.json({ valid: false });
        }

        if (isKeyExpired(keyDoc)) {
            return res.json({ valid: false, expired: true });
        }

        const timeInfo = getTimeRemaining(keyDoc);

        return res.json({
            valid: true,
            plan: keyDoc.plan,
            timeRemaining: timeInfo.text
        });

    } catch (error) {
        return res.json({ valid: false });
    }
});

/**
 * POST /check
 * Verificar status de uma key (sem HWID)
 * Body: { key: string }
 */
app.post('/check', async (req, res) => {
    try {
        const { key } = req.body;

        if (!key || !isValidKeyFormat(key)) {
            return res.json({ exists: false });
        }

        const keyDoc = await Key.findOne({ key: key.toUpperCase().trim() });

        if (!keyDoc) {
            return res.json({ exists: false });
        }

        return res.json({
            exists: true,
            active: keyDoc.active,
            plan: keyDoc.plan,
            expired: isKeyExpired(keyDoc)
        });

    } catch (error) {
        return res.json({ exists: false });
    }
});

// ═══════════════════════════════════════════════════════════════
// ADMIN ENDPOINTS (protegidos por API key)
// ═══════════════════════════════════════════════════════════════

const adminAuth = (req, res, next) => {
    const apiKey = req.headers['x-api-key'];
    if (!apiKey || apiKey !== process.env.ADMIN_API_KEY) {
        return res.status(401).json({ error: 'Não autorizado' });
    }
    next();
};

// Gerar nova key
app.post('/admin/generate', adminAuth, async (req, res) => {
    try {
        const { plan, count = 1 } = req.body;

        const planConfig = {
            '24h': { prefix: 'RP-H24', duration: 86400 },
            '7d': { prefix: 'RP-D07', duration: 604800 },
            '30d': { prefix: 'RP-D30', duration: 2592000 },
            'lifetime': { prefix: 'RP-LFT', duration: null }
        };

        if (!planConfig[plan]) {
            return res.status(400).json({ error: 'Plano inválido' });
        }

        const config = planConfig[plan];
        const keys = [];

        for (let i = 0; i < Math.min(count, 50); i++) {
            const randomPart = crypto.randomBytes(4).toString('hex').toUpperCase();
            const keyStr = `${config.prefix}-${randomPart}`;

            const newKey = new Key({
                key: keyStr,
                plan,
                duration: config.duration,
                active: false
            });

            await newKey.save();
            keys.push(keyStr);
        }

        return res.json({ success: true, keys });

    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
});

// Listar keys
app.get('/admin/keys', adminAuth, async (req, res) => {
    try {
        const { status, plan, limit = 100 } = req.query;

        const filter = {};
        if (status === 'active') filter.active = true;
        if (status === 'inactive') filter.active = false;
        if (plan) filter.plan = plan;

        const keys = await Key.find(filter)
            .sort({ createdAt: -1 })
            .limit(parseInt(limit));

        return res.json({ keys });

    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
});

// Resetar HWID de uma key
app.post('/admin/reset-hwid', adminAuth, async (req, res) => {
    try {
        const { key } = req.body;

        const keyDoc = await Key.findOneAndUpdate(
            { key: key.toUpperCase() },
            {
                hwid: null,
                active: false,
                activatedAt: null,
                expiresAt: null,
                attempts: 0,
                blockedUntil: null
            },
            { new: true }
        );

        if (!keyDoc) {
            return res.status(404).json({ error: 'Key não encontrada' });
        }

        return res.json({ success: true, key: keyDoc });

    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
});

// Desbloquear key
app.post('/admin/unblock', adminAuth, async (req, res) => {
    try {
        const { key } = req.body;

        const keyDoc = await Key.findOneAndUpdate(
            { key: key.toUpperCase() },
            { blockedUntil: null, attempts: 0 },
            { new: true }
        );

        if (!keyDoc) {
            return res.status(404).json({ error: 'Key não encontrada' });
        }

        return res.json({ success: true, key: keyDoc });

    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
});

// ═══════════════════════════════════════════════════════════════
// HEALTH CHECK & KEEP-ALIVE (sem rate limit)
// ═══════════════════════════════════════════════════════════════

// Endpoint raiz
app.get('/', (req, res) => {
    res.json({
        status: 'online',
        service: 'Royal Notifier License API',
        version: '2.0.0'
    });
});

// Health check padrão
app.get('/health', (req, res) => {
    res.json({ status: 'ok' });
});

// Ping simples para keep-alive (resposta mínima)
app.get('/ping', (req, res) => {
    res.status(200).send('pong');
});

// Wakeup endpoint (usado antes do login para acordar a API)
app.get('/wakeup', (req, res) => {
    res.json({
        awake: true,
        timestamp: Date.now()
    });
});

// ═══════════════════════════════════════════════════════════════
// START SERVER
// ═══════════════════════════════════════════════════════════════

const PORT = process.env.PORT || 3001;

app.listen(PORT, () => {
    console.log(`[API] ✅ Servidor rodando na porta ${PORT}`);
});
