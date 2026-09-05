FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN python -m pip install --no-cache-dir .
ENTRYPOINT ["agentir"]
CMD ["replay", "incidents/01-indirect-prompt-injection/events.jsonl"]
