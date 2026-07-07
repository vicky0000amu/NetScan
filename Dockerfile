# Use a slim Node image as the base
FROM node:20-slim

# Install nmap from Debian's package repo (this is the whole reason
# we can't use a plain serverless platform like Vercel — it has no
# apt-get and won't let us install system binaries)
RUN apt-get update && \
    apt-get install -y --no-install-recommends nmap && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install dependencies first (better Docker layer caching)
COPY package*.json ./
RUN npm install --omit=dev

# Copy the rest of the app
COPY . .

EXPOSE 3000

CMD ["node", "server.js"]
