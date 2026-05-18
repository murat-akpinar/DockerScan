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

# Stage 2: nginx — static dosyaları serve et + /api/ proxy
FROM nginx:alpine

RUN apk update && apk upgrade --no-cache && \
    apk add --no-cache ca-certificates wget && \
    rm -rf /var/cache/apk/*

COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx/nginx.conf /etc/nginx/nginx.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
