# ===========================================================================
# Frontend Dockerfile — AgentOps Security Mesh React Dashboard
# Multi-stage: Vite build → Nginx static serve
# ===========================================================================

# Stage 1: Builder — build the Vite production bundle
FROM node:20-alpine AS builder

WORKDIR /app

# Accept build-time env vars for Vite (prefix VITE_)
ARG VITE_API_URL=http://localhost:8000/api
ARG VITE_WS_URL=ws://localhost:8000/ws/dashboard

ENV VITE_API_URL=$VITE_API_URL
ENV VITE_WS_URL=$VITE_WS_URL

COPY package*.json ./
RUN npm install

COPY . .
RUN npm run build

# Stage 2: Runtime — serve via Nginx
FROM nginx:1.25-alpine AS runtime

# Remove default nginx page
RUN rm -rf /usr/share/nginx/html/*

# Copy built assets
COPY --from=builder /app/dist /usr/share/nginx/html

# Custom nginx config for SPA routing (all 404s → index.html)
RUN cat > /etc/nginx/conf.d/default.conf <<'EOF'
server {
    listen 80;
    server_name _;

    root /usr/share/nginx/html;
    index index.html;

    # SPA fallback
    location / {
        try_files $uri $uri/ /index.html;
    }

    # Cache static assets aggressively
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff2?)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    # Disable caching for index.html so new deploys are picked up
    location = /index.html {
        add_header Cache-Control "no-cache, no-store, must-revalidate";
    }

    gzip on;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml;
    gzip_min_length 256;
}
EOF

HEALTHCHECK --interval=15s --timeout=5s --retries=3 \
    CMD wget -qO- http://localhost:80 || exit 1

EXPOSE 80
