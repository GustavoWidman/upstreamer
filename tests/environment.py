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
    context.shared_kind_cluster = KindCluster()


def after_scenario(context, scenario):
    for backend in getattr(context, "backends", []):
        backend.stop()
    context.backends = []

    if getattr(context, "upstreamer", None):
        context.upstreamer.stop()
        context.upstreamer = None

    if "kubernetes" in scenario.effective_tags:
        context.shared_kind_cluster.reset_config()
        context.kind_cluster = None
    elif getattr(context, "kind_cluster", None):
        context.kind_cluster.cleanup()
        context.kind_cluster = None

    if getattr(context, "config_file", None):
        try:
            os.unlink(context.config_file)
        except OSError:
            pass
        context.config_file = None

    time.sleep(0.15)


def after_all(context):
    if getattr(context, "shared_kind_cluster", None):
        context.shared_kind_cluster.cleanup()
        context.shared_kind_cluster = None
