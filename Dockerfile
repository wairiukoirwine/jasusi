# Build the web app, then run the API which also serves it at /.
FROM node:22-alpine AS web
WORKDIR /web
COPY dashboard/package.json dashboard/package-lock.json ./
RUN npm ci
COPY dashboard/ ./
RUN npm run build

FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv
COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt
COPY backend/app backend/app
COPY ml/__init__.py ml/__init__.py
COPY ml/features ml/features
COPY --from=web /web/dist dashboard/dist
# Trained models are not in git. Mount them at /srv/ml/models (see docker-compose.yml);
# without them the API runs on its rule-based fallback.
RUN useradd --system --uid 10001 jasusi && mkdir -p /srv/ml/models && chown -R jasusi /srv
USER jasusi
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--app-dir", "backend", "--host", "0.0.0.0", "--port", "8000"]
