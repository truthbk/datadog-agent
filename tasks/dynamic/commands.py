from . import parsing
from .. import utils
from invoke import task


def _jobs_to_run():
    changed_files = utils.get_changed_files(ctx)
    return [""]

@task
def dynamic_run(ctx, full_pipeline=True):
    extender = parsing.GitlabExtender(ctx, source_ci_file=".dynamic.yml")
    extender.run()
    extender.deps_graph.resolve_stage_dep()
    if not full_pipeline:
        extender.deps_graph.pipeline_jobs_to_run(_jobs_to_run())

@task
def print_changed_files(ctx):
    print(utils.get_changed_files(ctx))


