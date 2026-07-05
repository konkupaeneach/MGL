require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const cookieParser = require('cookie-parser');
const { v4: uuidv4 } = require('uuid');
const useragent = require('useragent');
const geoip = require('geoip-lite');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Configuration de la base de données
const dbConfig = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
};

const pool = mysql.createPool(dbConfig);

// Middleware de sécurité
app.use(helmet());
app.use(cors({
    origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*',
    credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Configuration des sessions
const sessionStore = new MySQLStore({
    ...dbConfig,
    createDatabaseTable: true
});

app.use(session({
    key: 'secretmsg_session',
    secret: process.env.SESSION_SECRET,
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 86400000, // 24 heures
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax'
    }
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100,
    message: { error: 'Trop de requêtes, veuillez réessayer plus tard.' }
});

const messageLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 heure
    max: 10,
    message: { error: 'Limite de messages atteinte. Réessayez dans une heure.' }
});

app.use('/api/', limiter);
app.use('/api/messages/send', messageLimiter);

// Servir les fichiers statiques
app.use(express.static(path.join(__dirname, 'public')));

// Middleware d'authentification admin
const authenticateAdmin = async (req, res, next) => {
    try {
        const token = req.cookies.admin_token || req.headers.authorization?.split(' ')[1];
        
        if (!token) {
            return res.status(401).json({ error: 'Authentification requise' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        const [admins] = await pool.execute(
            'SELECT id, username, email, role FROM admins WHERE id = ? AND is_active = TRUE',
            [decoded.id]
        );

        if (admins.length === 0) {
            return res.status(401).json({ error: 'Admin non trouvé ou désactivé' });
        }

        req.admin = admins[0];
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Token invalide ou expiré' });
    }
};

// Middleware de tracking utilisateur
const trackUser = async (req, res, next) => {
    try {
        const ip = req.ip || req.connection.remoteAddress;
        const agent = useragent.parse(req.headers['user-agent']);
        const fingerprint = req.headers['x-fingerprint'] || 'unknown';
        
        req.userInfo = {
            ip_address: ip,
            user_agent: req.headers['user-agent'],
            browser_info: `${agent.family} ${agent.major}.${agent.minor}`,
            device_info: `${agent.os.family} ${agent.os.major}`,
            fingerprint: fingerprint,
            geo_location: geoip.lookup(ip) ? JSON.stringify(geoip.lookup(ip)) : null
        };
        
        next();
    } catch (error) {
        next();
    }
};

// Routes API

// 1. Enregistrement/Création d'utilisateur
app.post('/api/users/register', trackUser, async (req, res) => {
    try {
        const { username, email } = req.body;
        const uuid = uuidv4();
        
        const [result] = await pool.execute(
            'INSERT INTO users (uuid, username, email, ip_address, user_agent, fingerprint) VALUES (?, ?, ?, ?, ?, ?)',
            [uuid, username, email, req.userInfo.ip_address, req.userInfo.user_agent, req.userInfo.fingerprint]
        );
        
        // Créer un token utilisateur
        const userToken = jwt.sign(
            { id: result.insertId, uuid: uuid },
            process.env.JWT_SECRET,
            { expiresIn: '30d' }
        );
        
        res.cookie('user_token', userToken, {
            maxAge: 30 * 24 * 60 * 60 * 1000,
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production'
        });
        
        res.json({
            success: true,
            user_id: result.insertId,
            uuid: uuid
        });
    } catch (error) {
        console.error('Erreur enregistrement utilisateur:', error);
        res.status(500).json({ error: 'Erreur lors de l\'enregistrement' });
    }
});

// 2. Envoi de message anonyme
app.post('/api/messages/send', [
    body('content').trim().isLength({ min: 1, max: 500 }).withMessage('Le message doit faire entre 1 et 500 caractères'),
    body('username').trim().isLength({ min: 1, max: 100 }).withMessage('Le nom est requis'),
], trackUser, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { content, username, email } = req.body;
        
        // Vérifier si l'utilisateur existe déjà
        let [users] = await pool.execute(
            'SELECT id FROM users WHERE fingerprint = ? OR (email = ? AND email IS NOT NULL)',
            [req.userInfo.fingerprint, email]
        );

        let userId;
        
        if (users.length > 0) {
            userId = users[0].id;
            // Mettre à jour la dernière activité
            await pool.execute(
                'UPDATE users SET last_active = CURRENT_TIMESTAMP, ip_address = ? WHERE id = ?',
                [req.userInfo.ip_address, userId]
            );
        } else {
            // Créer un nouvel utilisateur
            const uuid = uuidv4();
            const [result] = await pool.execute(
                'INSERT INTO users (uuid, username, email, ip_address, user_agent, fingerprint) VALUES (?, ?, ?, ?, ?, ?)',
                [uuid, username, email, req.userInfo.ip_address, req.userInfo.user_agent, req.userInfo.fingerprint]
            );
            userId = result.insertId;
        }

        // Vérifier si l'utilisateur est bloqué
        const [blockedUsers] = await pool.execute(
            'SELECT is_blocked FROM users WHERE id = ?',
            [userId]
        );

        if (blockedUsers[0]?.is_blocked) {
            return res.status(403).json({ error: 'Vous avez été bloqué par l\'administrateur' });
        }

        // Créer le message
        const messageUuid = uuidv4();
        await pool.execute(
            `INSERT INTO messages (uuid, user_id, content, ip_address, geo_location, browser_info, device_info) 
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [
                messageUuid,
                userId,
                content,
                req.userInfo.ip_address,
                req.userInfo.geo_location,
                req.userInfo.browser_info,
                req.userInfo.device_info
            ]
        );

        res.json({
            success: true,
            message: 'Message envoyé avec succès',
            message_uuid: messageUuid
        });
    } catch (error) {
        console.error('Erreur envoi message:', error);
        res.status(500).json({ error: 'Erreur lors de l\'envoi du message' });
    }
});

// 3. Récupération des messages publics (anonymes)
app.get('/api/messages/public', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const offset = (page - 1) * limit;

        const [messages] = await pool.execute(
            `SELECT m.uuid, m.content, m.created_at, 
                    COUNT(l.id) as likes_count
             FROM messages m
             LEFT JOIN likes l ON m.id = l.message_id
             WHERE m.is_deleted = FALSE
             GROUP BY m.id
             ORDER BY m.created_at DESC
             LIMIT ? OFFSET ?`,
            [limit, offset]
        );

        const [total] = await pool.execute(
            'SELECT COUNT(*) as count FROM messages WHERE is_deleted = FALSE'
        );

        res.json({
            messages,
            pagination: {
                current_page: page,
                total_pages: Math.ceil(total[0].count / limit),
                total_messages: total[0].count
            }
        });
    } catch (error) {
        console.error('Erreur récupération messages:', error);
        res.status(500).json({ error: 'Erreur lors de la récupération des messages' });
    }
});

// 4. Connexion admin
app.post('/api/admin/login', [
    body('email').isEmail().withMessage('Email invalide'),
    body('password').isLength({ min: 6 }).withMessage('Mot de passe trop court')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { email, password } = req.body;

        const [admins] = await pool.execute(
            'SELECT * FROM admins WHERE email = ? AND is_active = TRUE',
            [email]
        );

        if (admins.length === 0) {
            return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
        }

        const admin = admins[0];
        const isValidPassword = await bcrypt.compare(password, admin.password_hash);

        if (!isValidPassword) {
            return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
        }

        // Créer le token JWT
        const token = jwt.sign(
            { id: admin.id, email: admin.email, role: admin.role },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        // Mettre à jour la dernière connexion
        await pool.execute(
            'UPDATE admins SET last_login = CURRENT_TIMESTAMP WHERE id = ?',
            [admin.id]
        );

        // Logger l'activité
        await pool.execute(
            'INSERT INTO activity_logs (admin_id, action, details, ip_address) VALUES (?, ?, ?, ?)',
            [admin.id, 'login', JSON.stringify({ method: 'password' }), req.ip]
        );

        res.cookie('admin_token', token, {
            maxAge: 24 * 60 * 60 * 1000,
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax'
        });

        res.json({
            success: true,
            admin: {
                id: admin.id,
                username: admin.username,
                email: admin.email,
                role: admin.role
            },
            token
        });
    } catch (error) {
        console.error('Erreur connexion admin:', error);
        res.status(500).json({ error: 'Erreur lors de la connexion' });
    }
});

// 5. Récupération des messages pour admin (avec détails expéditeurs)
app.get('/api/admin/messages', authenticateAdmin, async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 50;
        const offset = (page - 1) * limit;

        const [messages] = await pool.execute(
            `SELECT 
                m.id,
                m.uuid,
                m.content,
                m.ip_address,
                m.geo_location,
                m.browser_info,
                m.device_info,
                m.created_at,
                u.username as sender_name,
                u.email as sender_email,
                u.fingerprint,
                u.ip_address as sender_ip,
                u.created_at as sender_registered_at,
                u.last_active as sender_last_active,
                u.is_blocked as sender_blocked
             FROM messages m
             JOIN users u ON m.user_id = u.id
             WHERE m.is_deleted = FALSE
             ORDER BY m.created_at DESC
             LIMIT ? OFFSET ?`,
            [limit, offset]
        );

        const [total] = await pool.execute(
            'SELECT COUNT(*) as count FROM messages WHERE is_deleted = FALSE'
        );

        // Logger l'accès admin
        await pool.execute(
            'INSERT INTO activity_logs (admin_id, action, details, ip_address) VALUES (?, ?, ?, ?)',
            [req.admin.id, 'view_messages', JSON.stringify({ page, limit }), req.ip]
        );

        res.json({
            messages,
            pagination: {
                current_page: page,
                total_pages: Math.ceil(total[0].count / limit),
                total_messages: total[0].count
            }
        });
    } catch (error) {
        console.error('Erreur récupération messages admin:', error);
        res.status(500).json({ error: 'Erreur lors de la récupération des messages' });
    }
});

// 6. Bloquer/Débloquer un utilisateur
app.post('/api/admin/users/:userId/toggle-block', authenticateAdmin, async (req, res) => {
    try {
        const { userId } = req.params;
        
        const [users] = await pool.execute('SELECT is_blocked FROM users WHERE id = ?', [userId]);
        
        if (users.length === 0) {
            return res.status(404).json({ error: 'Utilisateur non trouvé' });
        }

        const newStatus = !users[0].is_blocked;
        
        await pool.execute(
            'UPDATE users SET is_blocked = ? WHERE id = ?',
            [newStatus, userId]
        );

        await pool.execute(
            'INSERT INTO activity_logs (admin_id, action, details, ip_address) VALUES (?, ?, ?, ?)',
            [req.admin.id, newStatus ? 'block_user' : 'unblock_user', JSON.stringify({ user_id: userId }), req.ip]
        );

        res.json({
            success: true,
            user_id: userId,
            is_blocked: newStatus
        });
    } catch (error) {
        console.error('Erreur toggle block:', error);
        res.status(500).json({ error: 'Erreur lors du blocage/déblocage' });
    }
});

// 7. Supprimer un message (soft delete)
app.delete('/api/admin/messages/:messageId', authenticateAdmin, async (req, res) => {
    try {
        const { messageId } = req.params;
        
        await pool.execute(
            'UPDATE messages SET is_deleted = TRUE, deleted_at = CURRENT_TIMESTAMP WHERE id = ?',
            [messageId]
        );

        await pool.execute(
            'INSERT INTO activity_logs (admin_id, action, details, ip_address) VALUES (?, ?, ?, ?)',
            [req.admin.id, 'delete_message', JSON.stringify({ message_id: messageId }), req.ip]
        );

        res.json({ success: true, message: 'Message supprimé' });
    } catch (error) {
        console.error('Erreur suppression message:', error);
        res.status(500).json({ error: 'Erreur lors de la suppression' });
    }
});

// 8. Statistiques admin
app.get('/api/admin/stats', authenticateAdmin, async (req, res) => {
    try {
        const [totalMessages] = await pool.execute(
            'SELECT COUNT(*) as count FROM messages WHERE is_deleted = FALSE'
        );
        
        const [totalUsers] = await pool.execute(
            'SELECT COUNT(*) as count FROM users'
        );
        
        const [messagesToday] = await pool.execute(
            'SELECT COUNT(*) as count FROM messages WHERE DATE(created_at) = CURDATE() AND is_deleted = FALSE'
        );
        
        const [blockedUsers] = await pool.execute(
            'SELECT COUNT(*) as count FROM users WHERE is_blocked = TRUE'
        );

        res.json({
            total_messages: totalMessages[0].count,
            total_users: totalUsers[0].count,
            messages_today: messagesToday[0].count,
            blocked_users: blockedUsers[0].count
        });
    } catch (error) {
        console.error('Erreur statistiques:', error);
        res.status(500).json({ error: 'Erreur lors de la récupération des statistiques' });
    }
});

// Route pour le frontend
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Démarrage du serveur
app.listen(PORT, async () => {
    console.log(`🚀 Serveur démarré sur le port ${PORT}`);
    
    // Créer l'admin par défaut si nécessaire
    try {
        const [admins] = await pool.execute('SELECT COUNT(*) as count FROM admins');
        
        if (admins[0].count === 0) {
            const hashedPassword = await bcrypt.hash(process.env.ADMIN_PASSWORD || 'Admin123!', 10);
            
            await pool.execute(
                'INSERT INTO admins (username, email, password_hash, role) VALUES (?, ?, ?, ?)',
                ['admin', process.env.ADMIN_EMAIL || 'admin@secretmsg.com', hashedPassword, 'super_admin']
            );
            
            console.log('✅ Compte admin créé avec succès');
        }
    } catch (error) {
        console.error('Erreur création admin:', error);
    }
});