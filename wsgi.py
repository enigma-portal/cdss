"""Explicit WSGI entry point for the CDSS app and its single collection worker."""

from run import app, prepare_runtime


prepare_runtime()
