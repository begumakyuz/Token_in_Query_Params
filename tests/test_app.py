import os
import pytest
from app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_vulnerable_endpoint(client):
    """L14 Query Param test: Doğru token geldiğinde 200 döner."""
    response = client.get('/vulnerable/download?token=secure_api_key_placeholder')
    assert response.status_code == 200
    assert b"Vulnerable Login Success" in response.data

def test_secure_endpoint_no_header(client):
    """Zorunlu Header yoksa 401 vermeli."""
    response = client.get('/secure/download')
    assert response.status_code == 401

def test_secure_endpoint_invalid_token(client):
    """Yanlış Header gelirse 403 vermeli."""
    response = client.get('/secure/download', headers={"Authorization": "Bearer WRONGBOY"})
    assert response.status_code == 403

def test_secure_endpoint_valid_token(client):
    """Doğru Authorization Header gelirse onay vermeli."""
    response = client.get('/secure/download', headers={"Authorization": "Bearer secure_api_key_placeholder"})
    assert response.status_code == 200
    assert b"Secure Login Success" in response.data
