"""
vrl namespaced tasks
"""
import errno
import os
import shutil
import sys

from invoke import task
from invoke.exceptions import Exit

def get_vrl_path():
    here = os.path.abspath(os.path.dirname(__file__))
    return os.path.abspath(os.path.join(here, '..', 'pkg/logs/vrl'))

@task 
def build(ctx):
    ctx.run(f"cd {get_vrl_path()} && cargo build --release")
