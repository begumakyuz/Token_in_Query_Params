FROM node:18-alpine

WORKDIR /usr/src/app

COPY package*.json ./
RUN npm install --production

COPY server.js ./

# Dummy Confidential Data
RUN echo "Vize Projesi: Token in Query Params Bypass - Gizli Veriye Erisim Saglandi!" > confidential.txt

EXPOSE 3000

CMD ["npm", "start"]
