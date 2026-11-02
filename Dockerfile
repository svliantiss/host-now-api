FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev
COPY server.mjs ./
ENV PORT=8799
EXPOSE 8799
CMD ["node", "server.mjs"]
