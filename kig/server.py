"""ASGI entry point: ``uvicorn --factory kig.server:app``."""
import os

from .api import create_app


def app():
    return create_app(os.environ.get("KIG_DATA", "./data"))
