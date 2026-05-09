import os
import time

from helpers import KindCluster, UPSTREAMER_BIN


def before_all(context):
    if not os.path.exists(UPSTREAMER_BIN):
        raise FileNotFoundError(
            f"upstreamer binary not found at {UPSTREAMER_BIN}. "
            "Run 'cargo build --release' first."
        )
    context.backends = []
    context.upstreamer = None
    context.config_file = None
    context.kind_cluster = None


def after_scenario(context, scenario):
    for backend in getattr(context, "backends", []):
        backend.stop()
    context.backends = []

    if getattr(context, "upstreamer", None):
        context.upstreamer.stop()
        context.upstreamer = None

    if getattr(context, "kind_cluster", None):
        context.kind_cluster.cleanup()
        context.kind_cluster = None

    if getattr(context, "config_file", None):
        try:
            os.unlink(context.config_file)
        except OSError:
            pass
        context.config_file = None

    time.sleep(0.15)
