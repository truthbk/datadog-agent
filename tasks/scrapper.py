from invoke import task
import pickle
import json
import time

DD_ID = 'DataDog%2Fdatadog-agent'
DATA_NB = 3000
faillure_list = {}
file_diff = {}


def get_pipeline_jobs(ctx, pipelineID):
    faillure_list[pipelineID] = []
    output = ctx.run(
        f"curl --header \"PRIVATE-TOKEN: $GITLAB_TOKEN\" \"https://gitlab.ddbuild.io/api/v4/projects/{DD_ID}/pipelines/{pipelineID}/jobs\"",
        hide=True,
    )
    content = json.loads(output.stdout)
    for job in content:
        if job["status"] == "failed":
            faillure_list[pipelineID].append(job["name"])


def get_recent_pipelines(ctx, upd_after=None):
    if not upd_after:
        output = ctx.run(
            f"curl --header \"PRIVATE-TOKEN: $GITLAB_TOKEN\" \"https://gitlab.ddbuild.io/api/v4/projects/{DD_ID}/pipelines?scope=finished\"",
            hide=True,
        )
    else:
        output = ctx.run(
            f"curl --header \"PRIVATE-TOKEN: $GITLAB_TOKEN\" \"https://gitlab.ddbuild.io/api/v4/projects/{DD_ID}/pipelines?scope=finished&updated_before={upd_after}\"",
            hide=True,
        )
    return json.loads(output.stdout)


def get_commit_diff(ctx, sha, pipelineID):
    output = ctx.run(
        f"curl --header \"PRIVATE-TOKEN: $GITLAB_TOKEN\" \"https://gitlab.ddbuild.io/api/v4/projects/{DD_ID}/repository/compare?from=main&to={sha}\"",
        hide=True,
    )
    content = json.loads(output.stdout)
    for diffs in content["diffs"]:
        file_diff[pipelineID] = [diffs["old_path"]]
        if diffs["new_path"] not in file_diff[pipelineID]:
            file_diff[pipelineID] = [diffs["new_path"]]


@task
def scrap(ctx):
    ctx.run("curl --header \"PRIVATE-TOKEN: $GITLAB_TOKEN\" https://gitlab.ddbuild.io/api/v4/projects")
    print("Gathering Recent pipelines...")
    latest_update = None
    batch_id = 0
    while len(file_diff.keys()) < DATA_NB:
        print("Batch : ", batch_id)
        pipeline_batch = get_recent_pipelines(ctx, latest_update)
        for pipeline in pipeline_batch:
            latest_update = pipeline["updated_at"]
            print(f"{pipeline['sha']}...")
            get_commit_diff(ctx, pipeline['sha'], pipeline['id'])
            print(f"{pipeline['id']}...")
            get_pipeline_jobs(ctx, pipeline["id"])
        batch_id += 1
        print("Small 2 sec break...")
        time.sleep(2)

    with open("data-save.pickle", "wb") as f:
        pickle.dump([faillure_list, file_diff], f)
