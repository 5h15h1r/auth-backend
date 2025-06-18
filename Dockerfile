FROM python:3.9

WORKDIR /fastapi-app

ENV APP_ENV=NONE

RUN pip install --upgrade pip

COPY requirements.txt .

RUN pip install -r requirements.txt

COPY . .

EXPOSE 8000

ENV OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://observability.mopid.me:4317
ENV OTEL_EXPORTER_OTLP_METRICS_ENDPOINT=http://observability.mopid.me:4319
ENV OTEL_EXPORTER_OTLP_INSECURE=true
ENV OTEL_SERVICE_NAME=mopid-auth-backend
ENV TRACES_EXPORTER=otlp
ENV METRICS_EXPORTER=otlp

CMD ["uvicorn", "app.main:app", "--proxy-headers", "--workers", "4","--host", "0.0.0.0", "--port", "8000"]