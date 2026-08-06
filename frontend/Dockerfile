# ── Stage 1: Build ──────────────────────────────────────────────
FROM node:20-alpine AS builder

ENV NODE_ENV=development

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts

COPY . .

# ── Stage 2: Development ────────────────────────────────────────
FROM node:20-alpine AS development

ENV NODE_ENV=development

WORKDIR /app

RUN addgroup --system --gid 1001 aegisx \
    && adduser --system --uid 1001 --ingroup aegisx aegisx

COPY --from=builder --chown=aegisx:aegisx /app /app
RUN chown aegisx:aegisx /app

USER aegisx:aegisx

EXPOSE 3000

CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]

# ── Stage 3: Production Build ───────────────────────────────────
FROM node:20-alpine AS build-prod

ENV NODE_ENV=production

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts

COPY . .

RUN npm run build

# ── Stage 4: Production Serve ───────────────────────────────────
FROM nginx:1.27-alpine AS production

ENV NODE_ENV=production

RUN rm -rf /etc/nginx/conf.d/default.conf

COPY --from=build-prod /app/dist /usr/share/nginx/html

COPY nginx-frontend.conf /etc/nginx/conf.d/default.conf

RUN addgroup --system --gid 1001 nginxgroup \
    && adduser --system --uid 1001 --ingroup nginxgroup nginxuser \
    && chown -R nginxuser:nginxgroup /usr/share/nginx/html \
    && chown -R nginxuser:nginxgroup /var/cache/nginx \
    && chown -R nginxuser:nginxgroup /var/log/nginx \
    && chown -R nginxuser:nginxgroup /etc/nginx

RUN touch /var/run/nginx.pid \
    && chown -R nginxuser:nginxgroup /var/run/nginx.pid

USER nginxuser:nginxgroup

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:80/health || exit 1

CMD ["nginx", "-g", "daemon off;"]
