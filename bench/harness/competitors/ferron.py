from ..servers import ALL, Server, exe

SERVER = Server(
    name="ferron",
    tool="ferron",
    capabilities=ALL,
    not_applicable={},
    template="ferron.kdl",
    argv=lambda ctx: [exe("ferron"), "--config", str(ctx.config)],
)
