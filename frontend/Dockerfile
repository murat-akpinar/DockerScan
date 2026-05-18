FROM node:20-alpine AS build

WORKDIR /app

RUN apk update && apk upgrade --no-cache && \
    apk add --no-cache ca-certificates && \
    rm -rf /var/cache/apk/*

ARG NPM_REGISTRY=
ARG VITE_API_BASE=http://localhost:3017
ENV VITE_API_BASE=${VITE_API_BASE}

COPY package.json package-lock.json* ./

RUN if [ -n "$NPM_REGISTRY" ]; then \
        npm config set registry "$NPM_REGISTRY"; \
        npm config set strict-ssl false; \
    fi && \
    npm ci --include=dev

COPY tsconfig.json vite.config.ts tailwind.config.ts postcss.config.cjs ./
COPY index.html ./
COPY public ./public
COPY src ./src

RUN npm run build
