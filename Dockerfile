FROM python:3.10-slim

# Rootless Docker (Adım 4 için spesifik gereksinim)
RUN useradd -m -u 1000 appuser

WORKDIR /app

# Bağımlılıkları kopyala ve as user kur (veya global kurup user'a geç)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Uygulama kodlarını kopyala ve sahipliğini appuser'a ver
COPY --chown=appuser:appuser app.py .

# Güvenliğe uygun rootless kullanıcıya geçiş yap
USER 1000

ENV FLASK_APP=app.py

EXPOSE 5000

# Flask dev server yerine production WSGI server (Gunicorn) kullanımı
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "app:app"]
