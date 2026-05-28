FROM python:3.12-slim

RUN pip install --no-cache-dir vllm
EXPOSE 8000
CMD ["vllm", "serve", "mistralai/Mistral-7B-Instruct-v0.3"]
