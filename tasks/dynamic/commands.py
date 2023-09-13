from . import parsing
from invoke import task

@task
def dynamic_run(ctx):
    extender = parsing.GitlabExtender(ctx, source_ci_file="dynamic.yml")
    extender.run()
    extender.deps_graph.resolve_stage_dep()
