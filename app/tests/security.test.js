const request = require('supertest');
const app = require('../server');

describe('Security API Endpoints Tests', () => {

    it('Vulnerable Endpoint: Should accept token via Query Parameters', async () => {
        const response = await request(app).get('/vulnerable/download?token=secure_api_key_placeholder');
        // confidential.txt test ortamında yaratılmadığı sürece "dosya bulunamadı" yanıtı dönse de yetkilendirme başarılı sayılır (200 OK)
        expect(response.statusCode).toBe(200);
    });

    it('Secure Endpoint: Should REJECT request without Authorization header', async () => {
        const response = await request(app).get('/secure/download');
        expect(response.statusCode).toBe(401);
        expect(response.body.error).toBeDefined();
    });

    it('Secure Endpoint: Should REJECT request with invalid token', async () => {
        const response = await request(app)
            .get('/secure/download')
            .set('Authorization', 'Bearer WRONG_TOKEN');
        expect(response.statusCode).toBe(403);
    });

    it('Secure Endpoint: Should ACCEPT valid token in Authorization Header', async () => {
        const response = await request(app)
            .get('/secure/download')
            .set('Authorization', 'Bearer secure_api_key_placeholder');
        // Valid token ile erişildiğinde 200 döner
        expect(response.statusCode).toBe(200);
    });

});
