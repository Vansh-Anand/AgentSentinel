ARG UI_BASE_IMAGE=public.ecr.aws/docker/library/node:24-bookworm-slim
FROM ${UI_BASE_IMAGE}

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
EXPOSE 5173
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0", "--port", "5173"]
