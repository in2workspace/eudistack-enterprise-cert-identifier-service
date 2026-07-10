FROM node:22-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY server/ ./server/
RUN chown -R node:node /app
USER node
EXPOSE 8080 3444
CMD ["node", "server/cert-server.mjs"]