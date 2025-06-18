# app/opentelemetry.py
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.instrumentation.pymysql import PyMySQLInstrumentor
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from functools import wraps

# from opentelemetry.instrumentation.pymongo import PymongoInstrumentor
from fastapi import FastAPI


def configure_opentelemetry(app: FastAPI):
    resource = Resource.create(attributes={"service.name": "mopid-auth-backend"})
    trace.set_tracer_provider(TracerProvider(resource=resource))
    span_processor = BatchSpanProcessor(
        OTLPSpanExporter(endpoint="http://observability.mopid.me:4317")
    )

    trace.get_tracer_provider().add_span_processor(span_processor)
    provider = trace.get_tracer_provider()

    # instrumentations
    PyMySQLInstrumentor().instrument(tracer_provider=provider)
    RequestsInstrumentor().instrument(tracer_provider=provider)
    FastAPIInstrumentor.instrument_app(app)


def otel_instrumentation():
    def decorator(func):
        @wraps(func)  # Preserve function metadata
        def wrapper(*args, **kwargs):
            provider = trace.get_tracer_provider()
            with provider.get_tracer(__name__).start_as_current_span(
                func.__name__
            ) as span:
                # Extract relevant attributes from common argument patterns
                if "sql" in kwargs:
                    span.set_attribute("sql", kwargs["sql"])
                if "query" in kwargs:
                    span.set_attribute("query", kwargs["query"])
                if "params" in kwargs:
                    span.set_attribute("params", kwargs["params"])
                if "data" in kwargs:
                    span.set_attribute("data", kwargs["data"])
                return func(*args, **kwargs)

        return wrapper

    return decorator
