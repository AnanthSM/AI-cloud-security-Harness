FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml constraints-dev.txt README.md LICENSE ./
COPY src ./src
COPY mcp_servers ./mcp_servers
RUN pip install --no-cache-dir -c constraints-dev.txt . && useradd --create-home --uid 10001 harness
COPY config ./config
COPY agents ./agents
COPY skills ./skills
COPY policies ./policies
COPY knowledge ./knowledge
COPY evals ./evals
RUN mkdir -p /app/.state && chown -R harness:harness /app
USER harness
EXPOSE 8000
CMD ["harness", "serve", "--host", "0.0.0.0"]
