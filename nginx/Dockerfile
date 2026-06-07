# Stage 1: React frontend build
FROM node:20-alpine AS build

WORKDIR /app

RUN apk update && apk upgrade --no-cache && \
    apk add --no-cache ca-certificates && \
    rm -rf /var/cache/apk/*

ARG VITE_API_BASE=
ENV VITE_API_BASE=${VITE_API_BASE}

COPY frontend/package.json frontend/package-lock.json* ./
RUN npm ci --include=dev

COPY frontend/tsconfig.json frontend/vite.config.ts frontend/tailwind.config.ts frontend/postcss.config.cjs ./
COPY frontend/index.html ./
COPY frontend/public ./public
COPY frontend/src ./src

RUN npm run build

# Stage 2: nginx — static dosyalari serve et + /api/ proxy
FROM nginx:alpine

RUN apk update && apk upgrade --no-cache && \
    apk add --no-cache ca-certificates wget && \
    rm -rf /var/cache/apk/*

COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx/nginx.conf /etc/nginx/nginx.conf

# nginx kullanicisinin yazabilmesi icin gerekli dizin izinleri
RUN chown -R nginx:nginx /usr/share/nginx/html \
                         /var/cache/nginx \
                         /var/log/nginx \
                         /etc/nginx/conf.d && \
    touch /var/run/nginx.pid && \
    chown nginx:nginx /var/run/nginx.pid

USER nginx

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD wget -q -O /dev/null http://localhost:8080/health || exit 1

CMD ["nginx", "-g", "daemon off;"]
