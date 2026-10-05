FROM node:22-alpine
WORKDIR /app
COPY package.json ./
COPY src ./src
ENV NODE_ENV=production PORT=8080 HOST=0.0.0.0
EXPOSE 8080
USER node
CMD ["node", "src/web/server.js"]
