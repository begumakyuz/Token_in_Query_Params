const express = require('express');
const crypto = require('crypto');
const fs = require('fs');

const app = express();
const PORT = 3000;

const VALID_TOKEN = process.env.API_SECRET_KEY || 'secure_api_key_placeholder'; 

// Gizli dosya içeriği (Dummy data)
const confidentialDataPath = '/usr/src/app/confidential.txt';

// --- VULNERABLE ENDPOINT ---
// SAST tarafından yakalanacak kötü örnek: 
// 1. `req.query.token` kullanılıyor (Token in Query Params)
// 2. Token doğrudan loglarda görünebilir
app.get('/vulnerable/download', (req, res) => {
    const userToken = req.query.token;

    if (userToken === VALID_TOKEN) {
        if (fs.existsSync(confidentialDataPath)) {
            res.download(confidentialDataPath);
        } else {
            res.json({ message: 'Yetkili giris basarili, ancak dosya bulunamadi.' });
        }
    } else {
        res.status(401).json({ error: 'Yetkisiz Erisim! (Zafiyetli Endpoint)' });
    }
});

// --- SECURE ENDPOINT ---
// Nginx üzerinden Authorization: Bearer Header ile aktarılır
app.get('/secure/download', (req, res) => {
    const authHeader = req.headers['authorization'];
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Eksik veya Gecersiz Yetki Basligi (Secure Endpoint).' });
    }

    const token = authHeader.split(' ')[1];

    try {
        // Timing Attack'e karşı kriptografik zaman korumalı karşılaştırma
        if (crypto.timingSafeEqual(Buffer.from(token), Buffer.from(VALID_TOKEN))) {
             if (fs.existsSync(confidentialDataPath)) {
                 res.download(confidentialDataPath);
             } else {
                 res.json({ message: 'Yetkili giris basarili, ancak dosya bulunamadi.' });
             }
        } else {
            res.status(403).json({ error: 'Erisim Reddedildi! Gecersiz Token.' });
        }
    } catch (e) {
        res.status(403).json({ error: 'Erisim Reddedildi! Gecersiz Token Belirteci.' });
    }
});

if (require.main === module) {
    app.listen(PORT, () => console.log(`Backend Servisi ${PORT} portunda dinliyor...`));
}

module.exports = app;
