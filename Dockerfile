FROM node:22-alpine
WORKDIR /app
COPY package.json identity.js server.js gateway.js rar.js foundation-server.js ./
COPY public ./public
RUN mkdir -p /app/state && chown node:node /app/state
USER node
EXPOSE 4191
CMD ["node", "foundation-server.js"]
