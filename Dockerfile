# syntax=docker/dockerfile:1
# Build:  docker build -t hb-eval-gateway .                       (with production embeddings)
#         docker build --build-arg WITH_EMBEDDINGS=0 -t hb-eval-gateway .   (lightweight smoke test)
FROM python:3.12-slim-bookworm AS build
ARG WITH_EMBEDDINGS=1
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
COPY requirements.lock requirements-embeddings.txt ./
COPY vendor/ ./vendor/
# Hash-pinned: a tampered or substituted package fails the build.
RUN pip install --require-hashes -r requirements.lock
# The SDK is installed separately so a new SDK release does not require re-locking (see requirements.lock).
WORKDIR /build/vendor
RUN sha256sum -c SHA256SUMS && pip install --no-deps ./*.whl && pip check \
 && if [ "$WITH_EMBEDDINGS" = "1" ]; then \
      pip install --index-url https://download.pytorch.org/whl/cpu torch \
      && pip install -r /build/requirements-embeddings.txt \
      && pip check \
      && python -c "from sentence_transformers import SentenceTransformer"; \
    fi

FROM python:3.12-slim-bookworm
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PATH="/opt/venv/bin:$PATH"
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin gateway
COPY --from=build /opt/venv /opt/venv
WORKDIR /app
COPY --chown=gateway:gateway *.py ./
USER 10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:%s/health' % os.environ.get('PORT','8000'), timeout=4)"]
# serve.py reads PORT and trusts the host's proxy headers only for FORWARDED_ALLOW_IPS.
CMD ["python", "serve.py"]
