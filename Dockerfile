FROM node:22-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY identity.js server.js gateway.js rar.js pcf.js duo-sso.js foundation-server.js ./
COPY public ./public
RUN chmod 755 /app /app/public && chmod 644 /app/*.js /app/package.json /app/public/* \
    && mkdir -p /app/state && chown node:node /app/state
USER node
EXPOSE 4191
CMD ["node", "foundation-server.js"]
