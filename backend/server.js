const express = require('express')
const dotenv = require('dotenv')
const { MongoClient } = require('mongodb'); 
const crypto = require('crypto')
const bodyparser = require('body-parser')
const cors = require('cors')

dotenv.config()


// Connecting to the MongoDB Client
const url = process.env.MONGO_URI;
const client = new MongoClient(url);
client.connect();

// App & Database
const dbName = process.env.DB_NAME 
const app = express()
const port = 3000 

// Middleware
app.use(bodyparser.json())
app.use(cors())

// Secure comparison middleware. The vulnerable routes intentionally retain
// Express defaults so the header differences are visible in the lab.
app.use('/api/lab/secure', (req, res, next) => {
    res.removeHeader('X-Powered-By');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'; base-uri 'none'");
    next();
});

const demoUsers = {
    'demo-user': {
        password: 'VulnLab-demo-only',
        passwordHash: crypto.scryptSync('VulnLab-demo-only', 'vulnlab-demo-salt', 64).toString('hex')
    }
};
const loginAttempts = new Map();
const issuedTokens = new Map();

const getLoginInput = (req, res) => {
    const { username, password } = req.body || {};
    if (typeof username !== 'string' || typeof password !== 'string') {
        res.status(400).json({ success: false, error: 'username and password are required' });
        return null;
    }
    return { username, password };
};

const issueLabToken = (username) => {
    const token = crypto.randomBytes(24).toString('hex');
    issuedTokens.set(token, { username, createdAt: Date.now() });
    return token;
};

const getRecordOwner = (req, res) => {
    const userId = getLabUserId(req, res);
    return userId;
};

const isValidSecureRecord = (record) => {
    const allowedKeys = ['id', 'site', 'username', 'password', 'notes'];
    const keys = Object.keys(record);
    if (keys.some(key => !allowedKeys.includes(key))) return false;
    if (!['id', 'site', 'username', 'password'].every(key => typeof record[key] === 'string')) return false;
    if (record.notes !== undefined && typeof record.notes !== 'string') return false;
    if (record.id.length < 1 || record.id.length > 100) return false;
    if (record.site.length < 1 || record.site.length > 2048) return false;
    if (record.username.length < 1 || record.username.length > 128) return false;
    if (record.password.length < 12 || record.password.length > 256) return false;
    if (record.notes && record.notes.length > 2000) return false;
    try {
        const siteUrl = new URL(record.site);
        if (!['http:', 'https:'].includes(siteUrl.protocol)) return false;
    } catch {
        return false;
    }
    return true;
};

// Intentionally vulnerable: accepts arbitrary fields and does only a minimal
// object check, leaving important validation to the client.
app.post('/api/lab/vulnerable/records', async (req, res) => {
    const userId = getRecordOwner(req, res);
    if (!userId) return;

    if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
        return res.status(400).json({ success: false, error: 'A JSON object is required' });
    }
    const result = await client.db(dbName).collection('passwords').insertOne({
        ...req.body,
        ownerId: userId
    });
    res.status(201).json({ success: true, id: result.insertedId });
});

// Secure comparison endpoint: validates the complete record on the server
// and stores only the approved fields plus the derived owner context.
app.post('/api/lab/secure/records', async (req, res) => {
    const userId = getRecordOwner(req, res);
    if (!userId) return;

    const record = req.body;
    if (!record || typeof record !== 'object' || Array.isArray(record) || !isValidSecureRecord(record)) {
        return res.status(400).json({
            success: false,
            error: 'Record must contain valid id, HTTP(S) site, username, password, and optional notes'
        });
    }

    const { id, site, username, password, notes = '' } = record;
    const result = await client.db(dbName).collection('passwords').insertOne({
        id,
        site,
        username,
        password,
        notes,
        ownerId: userId
    });
    res.status(201).json({ success: true, id: result.insertedId });
});


// Intentionally vulnerable: no rate limit and direct plaintext comparison.
app.post('/api/lab/auth/vulnerable/login', (req, res) => {
    const credentials = getLoginInput(req, res);
    if (!credentials) return;

    const user = demoUsers[credentials.username];
    if (!user || credentials.password !== user.password) {
        return res.status(401).json({ success: false, error: 'Invalid username or password' });
    }
    res.json({ success: true, token: issueLabToken(credentials.username) });
});

// Secure comparison endpoint: rate limits by client IP and compares a derived
// key using timing-safe equality instead of storing a plaintext comparison.
app.post('/api/lab/auth/secure/login', (req, res) => {
    const credentials = getLoginInput(req, res);
    if (!credentials) return;

    const now = Date.now();
    const key = req.ip;
    const attempt = loginAttempts.get(key) || { count: 0, firstAttemptAt: now };
    if (now - attempt.firstAttemptAt > 60_000) {
        attempt.count = 0;
        attempt.firstAttemptAt = now;
    }
    attempt.count += 1;
    loginAttempts.set(key, attempt);
    if (attempt.count > 5) {
        return res.status(429).json({ success: false, error: 'Too many login attempts' });
    }

    const user = demoUsers[credentials.username];
    const suppliedHash = crypto.scryptSync(credentials.password, 'vulnlab-demo-salt', 64);
    const expectedHash = Buffer.from(user ? user.passwordHash : '0'.repeat(128), 'hex');
    const valid = suppliedHash.length === expectedHash.length &&
        crypto.timingSafeEqual(suppliedHash, expectedHash);
    if (!user || !valid) {
        return res.status(401).json({ success: false, error: 'Invalid username or password' });
    }

    loginAttempts.delete(key);
    res.json({ success: true, token: issueLabToken(credentials.username) });
});


// Get all the passwords
app.get('/', async (req, res) => {
    const db = client.db(dbName);
    const collection = db.collection('passwords');
    const findResult = await collection.find({}).toArray();
    res.json(findResult)
})

// Save a password
app.post('/', async (req, res) => { 
    const password = req.body
    const db = client.db(dbName);
    const collection = db.collection('passwords');
    const findResult = await collection.insertOne(password);
    res.send({success: true, result: findResult})
})

// Delete a password by id
app.delete('/', async (req, res) => { 
    const password = req.body
    const db = client.db(dbName);
    const collection = db.collection('passwords');
    const findResult = await collection.deleteOne(password);
    res.send({success: true, result: findResult})
})

// Access-control lab routes use a synthetic local identity. The existing root
// routes remain unchanged so the original password-manager UI keeps working.
const getLabUserId = (req, res) => {
    const userId = req.get('X-VulnLab-User');
    if (!userId || typeof userId !== 'string' || userId.length > 64) {
        res.status(401).json({ success: false, error: 'X-VulnLab-User is required' });
        return null;
    }
    return userId;
};

// Lab setup endpoint: records created here are assigned to the local caller.
app.post('/api/lab/passwords', async (req, res) => {
    const userId = getLabUserId(req, res);
    if (!userId) return;

    const { id, site, username, password } = req.body;
    if (![id, site, username, password].every(value => typeof value === 'string' && value.length > 0)) {
        return res.status(400).json({ success: false, error: 'id, site, username, and password are required' });
    }

    const db = client.db(dbName);
    const result = await db.collection('passwords').insertOne({
        id,
        site,
        username,
        password,
        ownerId: userId
    });
    res.status(201).json({ success: true, id: result.insertedId });
});

// Intentionally vulnerable: authentication is simulated, but ownership is not checked.
app.get('/api/lab/vulnerable/passwords/:id', async (req, res) => {
    if (!getLabUserId(req, res)) return;

    const record = await client.db(dbName).collection('passwords').findOne({ id: req.params.id });
    if (!record) {
        return res.status(404).json({ success: false, error: 'Password record not found' });
    }
    res.json(record);
});

// Secure comparison endpoint: the record must belong to the synthetic caller.
app.get('/api/lab/secure/passwords/:id', async (req, res) => {
    const userId = getLabUserId(req, res);
    if (!userId) return;

    const record = await client.db(dbName).collection('passwords').findOne({
        id: req.params.id,
        ownerId: userId
    });
    if (!record) {
        return res.status(404).json({ success: false, error: 'Password record not found' });
    }
    res.json(record);
});

// Intentionally vulnerable mutation: the caller can delete any known record ID.
app.delete('/api/lab/vulnerable/passwords/:id', async (req, res) => {
    if (!getLabUserId(req, res)) return;

    const result = await client.db(dbName).collection('passwords').deleteOne({ id: req.params.id });
    if (result.deletedCount !== 1) {
        return res.status(404).json({ success: false, error: 'Password record not found' });
    }
    res.json({ success: true });
});

// Secure comparison endpoint: deletion is scoped to the synthetic caller.
app.delete('/api/lab/secure/passwords/:id', async (req, res) => {
    const userId = getLabUserId(req, res);
    if (!userId) return;

    const result = await client.db(dbName).collection('passwords').deleteOne({
        id: req.params.id,
        ownerId: userId
    });
    if (result.deletedCount !== 1) {
        return res.status(404).json({ success: false, error: 'Password record not found' });
    }
    res.json({ success: true });
});

// Intentionally vulnerable: the caller-controlled filter is merged after the
// owner filter, so MongoDB operators and ownerId overrides are accepted.
app.post('/api/lab/vulnerable/search', async (req, res) => {
    const userId = getLabUserId(req, res);
    if (!userId) return;

    const filter = req.body;
    if (!filter || typeof filter !== 'object' || Array.isArray(filter)) {
        return res.status(400).json({ success: false, error: 'A JSON filter object is required' });
    }

    const records = await client.db(dbName).collection('passwords').find({
        ownerId: userId,
        ...filter
    }).toArray();
    res.json(records);
});

// Secure comparison endpoint: accepts only a plain text site search and
// always applies the authenticated synthetic user's ownership constraint.
app.post('/api/lab/secure/search', async (req, res) => {
    const userId = getLabUserId(req, res);
    if (!userId) return;

    const { site } = req.body;
    if (site !== undefined && typeof site !== 'string') {
        return res.status(400).json({ success: false, error: 'site must be a string' });
    }

    const escapedSite = site ? site.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') : '';
    const filter = { ownerId: userId };
    if (escapedSite) {
        filter.site = { $regex: escapedSite, $options: 'i' };
    }

    const records = await client.db(dbName).collection('passwords').find(filter, {
        projection: { id: 1, site: 1, username: 1 }
    }).toArray();
    res.json(records);
});

// Intentionally vulnerable: returns complete password documents, including
// plaintext secrets and internal MongoDB fields.
app.get('/api/lab/vulnerable/export', async (req, res) => {
    const userId = getLabUserId(req, res);
    if (!userId) return;

    const records = await client.db(dbName).collection('passwords').find({
        ownerId: userId
    }).toArray();
    res.json({ userId, records });
});

// Secure comparison endpoint: returns only fields needed for a record listing.
app.get('/api/lab/secure/export', async (req, res) => {
    const userId = getLabUserId(req, res);
    if (!userId) return;

    const records = await client.db(dbName).collection('passwords').find({
        ownerId: userId
    }, {
        projection: { _id: 0, id: 1, site: 1, username: 1 }
    }).toArray();
    res.json({ records });
});

// Intentionally vulnerable: exposes runtime and implementation details that
// are unnecessary for a client and useful for server fingerprinting.
app.get('/api/lab/vulnerable/diagnostics', (req, res) => {
    res.json({
        server: 'Express',
        nodeVersion: process.version,
        platform: process.platform,
        database: dbName,
        environment: process.env.NODE_ENV || 'development',
        routes: ['/api/lab/vulnerable', '/api/lab/secure']
    });
});

// Secure comparison endpoint: exposes only a stable health response.
app.get('/api/lab/secure/diagnostics', (req, res) => {
    res.json({ service: 'VulnLab API', status: 'ok' });
});

// Intentionally vulnerable: arbitrary fields can be written to any record ID.
app.put('/api/lab/vulnerable/passwords/:id', async (req, res) => {
    if (!getLabUserId(req, res)) return;
    if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
        return res.status(400).json({ success: false, error: 'A JSON object is required' });
    }

    const result = await client.db(dbName).collection('passwords').updateOne(
        { id: req.params.id },
        { $set: req.body }
    );
    if (result.matchedCount !== 1) {
        return res.status(404).json({ success: false, error: 'Password record not found' });
    }
    res.json({ success: true });
});

// Secure comparison endpoint: updates only approved fields on an owned record.
app.patch('/api/lab/secure/passwords/:id', async (req, res) => {
    const userId = getLabUserId(req, res);
    if (!userId) return;
    const body = req.body;
    const allowedKeys = ['site', 'username', 'password', 'notes'];
    if (!body || typeof body !== 'object' || Array.isArray(body) ||
        Object.keys(body).some(key => !allowedKeys.includes(key)) ||
        Object.keys(body).length === 0 ||
        Object.values(body).some(value => typeof value !== 'string')) {
        return res.status(400).json({ success: false, error: 'Only string site, username, password, or notes fields are allowed' });
    }

    const result = await client.db(dbName).collection('passwords').updateOne(
        { id: req.params.id, ownerId: userId },
        { $set: body }
    );
    if (result.matchedCount !== 1) {
        return res.status(404).json({ success: false, error: 'Password record not found' });
    }
    res.json({ success: true });
});


app.listen(port, () => {
    console.log(`Example app listening on  http://localhost:${port}`)
})