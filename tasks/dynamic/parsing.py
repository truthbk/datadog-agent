from dataclasses import dataclass

import oyaml as yaml
import glob
from . import dependency_graph
import re
import os

"""
Yaml Loader edit to allow '!reference' tags support
"""


@dataclass
class reference:
    content: str


class Loader(yaml.SafeLoader):
    pass


class Dumper(yaml.Dumper):
    def process_scalar(self):
        if self.analysis is None:
            self.analysis = self.analyze_scalar(self.event.value)
        if self.style is None:
            self.style = self.choose_scalar_style()
        split = (not self.simple_key_context)
        # if self.analysis.multiline and split    \
        #        and (not self.style or self.style in '\'\"'):
        #    self.write_indent()
        if self.analysis.scalar.startswith("!reference"):
            self.style = ""

        if self.style == '"':
            self.write_double_quoted(self.analysis.scalar, split)
        elif self.style == '\'':
            self.write_single_quoted(self.analysis.scalar, split)
        elif self.style == '>':
            self.write_folded(self.analysis.scalar)
        elif self.style == '|':
            self.write_literal(self.analysis.scalar)
        else:
            self.write_plain(self.analysis.scalar, split)
        self.analysis = None
        self.style = None


class AsHex:
    def __init__(self, data):
        self.data = data

    def __repr__(self):
        return self.data


def represent_hex(dumper, data):
    # return yaml.Dumper.represent_tuple(dumper, data.data)
    # return yaml.ScalarNode("tag:yaml.org,2002:int", data, style="")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data.data, style='')


yaml.add_representer(AsHex, represent_hex)


def construct_reference(loader, node):
    content = str(node.tag + "[" + ",".join([e.value for e in node.value]) + "]")
    return AsHex(content)
    # return reference(node.tag+"["+",".join([e.value for e in node.value])+"]")


Loader.add_constructor("!reference", construct_reference)

def ignore(loader, tag, node):
    classname = node.__class__.__name__
    if (classname == 'SequenceNode'):
        resolved = loader.construct_sequence(node)
    elif (classname == 'MappingNode'):
        resolved = loader.construct_mapping(node)
    else:
        resolved = loader.construct_scalar(node)
    return resolved

yaml.add_multi_constructor('!', ignore, Loader=yaml.SafeLoader)
yaml.add_multi_constructor('', ignore, Loader=yaml.SafeLoader)


def createAndOpen(filename, mode):
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    return open(filename, mode)


class InvalidGitlabYamlExtension(Exception):
    """
    Custom Yaml Parsing Exception
    """

    def __init__(self, yaml_content, message="Invalid Gitlab Extension !"):
        self.yaml_content = yaml_content
        self.message = message + "\nYaml Content :\n" + str(self.yaml_content)
        super().__init__(self.message)


class Condition:
    """
    :name Condition's name
    :cmds Commands that define the condition value
    :condition_value Result value of the condition
    """

    def __init__(self, name, cmds):
        self.name = name
        self.cmds = cmds
        self.condition_value = None

    def __str__(self):
        return f"{self.name}: {self.condition_value}"

    def execute(self, ctx):
        if not self.cmds:
            return
        for cmd in self.cmds:
            result = ctx.run(cmd, hide=True)
        self.condition_value = result.return_code == 0


class GitlabExtender:
    def __init__(self, invoke_ctx, source_folder=".gitlab", source_ci_file=".gitlab-ci.yml", output_folder="dynamic",
                 debug_log=False):
        self.deps_graph = dependency_graph.DepGraph()
        self.gitlab_folder = source_folder
        self.gitlab_ci_file = source_ci_file
        self.ctx = invoke_ctx
        self.conditions = {}
        self.function_registry = {}
        self.extend_buffer = {}
        self.extend_save = []
        self.dep_root = None
        self.output_folder = output_folder
        self.debug_log = debug_log
        isExist = os.path.exists(self.output_folder)
        if not isExist:
            os.makedirs(self.output_folder)

    def list_jobs_dependencies(self):
        print("Ghost dependency ignored : ", len(self.deps_graph.ghost_edges))
        self.dep_root = self.deps_graph.root
        data = {}
        queue = [(self.dep_root, None)]
        while queue:
            node, parent = queue.pop(0)
            node.data = True
            if parent is not None:
                if data.get(node.name, None) is None:
                    data[node.name] = [parent.name]
                elif parent.name not in data[node.name]:
                    data[node.name].append(parent.name)
            for child in node.children:
                if not child.data:
                    queue.append((child, node))
        return data

    def condition_parse(self, condition_content):
        for condition_name in condition_content:
            new_condition = Condition(condition_name, condition_content[condition_name])
            try:
                new_condition.execute(self.ctx)
            except Exception as e:
                new_condition.condition_value = False
            self.conditions[condition_name] = new_condition

    def if_parse(self, if_content):
        if not (2 <= len(if_content) <= 3):
            raise InvalidGitlabYamlExtension(if_content,
                                             f"Gitlab(If): invalid nested element number expected 2 or 3 got {len(if_content)}")

        condition_name = if_content[0]
        true_statement = if_content[1]
        false_statement = if_content[2]

        condition_obj = self.conditions.get(condition_name, None)
        if condition_obj is None:
            raise InvalidGitlabYamlExtension(if_content, f"Gitlab(If): Condition {condition_name} not found !")

        if condition_obj.condition_value:
            return true_statement

        return false_statement

    def extended_content(self, yaml_content):
        ext_functions = yaml_content["extends"]
        if type(ext_functions) != list:
            ext_functions = [ext_functions]
        for ext_func in ext_functions:
            if ext_func not in self.function_registry.keys():
                print("[WARN] Function Registry not found : ", ext_func)
                return yaml_content
            else:
                extension = self.function_registry[ext_func]
                if extension.get("extends", None) is not None:
                    extension = self.extended_content(extension)
                extension_copy = extension.copy()
                extension_copy.update(yaml_content)
                return extension_copy

    def quick_function_explorer(self, yaml_content, parentKey=None):
        if type(yaml_content) == list:
            for content in yaml_content:
                self.quick_function_explorer(content)
        elif type(yaml_content) == dict:
            if yaml_content.get("extends", None) is not None:
                value = yaml_content["extends"]
                if type(value) != list:
                    value = [value]
                for ext in value:
                    if ext[0] != ".":
                        self.extend_save.append(ext)

            if parentKey is not None and parentKey[0] == ".":
                self.function_registry[parentKey] = yaml_content
            elif yaml_content.get("stage", None) is not None or yaml_content.get("extends", None) is not None:
                self.extend_buffer[parentKey] = yaml_content
            for key in yaml_content:
                self.quick_function_explorer(yaml_content[key], key)

    def yaml_explorer(self, yaml_content, parentKey=None):
        if type(yaml_content) == list:
            for content in yaml_content:
                self.yaml_explorer(content)
        elif type(yaml_content) == dict:
            if yaml_content.get("ext-if", None) is not None:
                result = self.if_parse(yaml_content["ext-if"])
                key = list(result.keys())[0]
                yaml_content[key] = result[key]
                yaml_content.pop("ext-if")
            if parentKey is not None and parentKey[0] == ".":
                pass
            elif yaml_content.get("extends", None) is not None:
                new_content = self.extended_content(yaml_content)
                deps = []
                if new_content.get("needs", None) is not None:
                    deps = new_content["needs"]
                if new_content.get("stage", None) is not None:
                    self.deps_graph.append_node(parentKey, new_content["stage"], deps)
                else:
                    if self.debug_log:
                        print("stage not found on ", parentKey)
                    self.deps_graph.append_node(parentKey, "no-stage", deps)
            elif yaml_content.get("stage", None) is not None:
                deps = []
                if yaml_content.get("needs", None) is not None:
                    deps = yaml_content["needs"]
                    if not deps:
                        deps = None
                self.deps_graph.append_node(parentKey, yaml_content["stage"], deps)
            for key in yaml_content:
                self.yaml_explorer(yaml_content[key], key)

    def parse_file(self, file_path, gen_dep=False):
        if self.debug_log:
            print(f"Parsing {file_path}...")
        with open(file_path, "r") as f:
            yaml_content = yaml.load(f.read(), Loader=Loader)
        condition_content = yaml_content.get("conditions", None)
        if condition_content is not None:
            self.condition_parse(condition_content)
            yaml_content.pop("conditions")

        self.yaml_explorer(yaml_content)
        output_name = file_path.split("/")
        if self.gitlab_folder in output_name:
            output_name.remove(self.gitlab_folder)

        with createAndOpen(f"{self.output_folder}/" + "/".join(output_name), "w") as f:
            yaml.dump(yaml_content, f, Dumper=Dumper)

    def quick_function_first_read(self, file_path):
        with open(file_path, "r") as f:
            yaml_content = yaml.load(f.read(), Loader=Loader)
        self.quick_function_explorer(yaml_content)

        for to_extend in self.extend_save:
            self.function_registry[to_extend] = self.extend_buffer[to_extend]

        self.extend_buffer.clear()
        self.extend_save.clear()

    def run(self):
        self.quick_function_first_read(self.gitlab_ci_file)
        for file in glob.glob(self.gitlab_folder + "/**/*.yml", recursive=True):
            self.quick_function_first_read(file)

        self.parse_file(self.gitlab_ci_file)
        for file in glob.glob(self.gitlab_folder + "/**/*.yml", recursive=True):
            self.parse_file(file)

    def yaml_applier(self, yaml_content, enabledJobs, parentKey=None):
        if type(yaml_content) == list:
            for content in yaml_content:
                self.yaml_applier(content, enabledJobs)
        elif type(yaml_content) == dict:
            if parentKey is not None and parentKey[0] == ".":
                pass
            elif yaml_content.get("stage", None) is not None:
                if parentKey not in enabledJobs:
                    yaml_content["when"] = "never"

            for key in yaml_content:
                self.yaml_applier(yaml_content[key], enabledJobs, key)

    def apply_on_file(self, file_path, enabledJobs):
        with open(file_path, "r") as f:
            yaml_content = yaml.load(f.read(), Loader=yaml.SafeLoader)

        self.yaml_applier(yaml_content, enabledJobs)
        output_name = file_path.split("/")
        if self.gitlab_folder in output_name:
            output_name.remove(self.gitlab_folder)

        with createAndOpen(f"{self.output_folder}/" + "/".join(output_name), "w") as f:
            yaml.dump(yaml_content, f, Dumper=Dumper)
        with open(f"{self.output_folder}/" + "/".join(output_name), "r") as f:
            content = f.read()
        with open(f"{self.output_folder}/" + "/".join(output_name), "w") as f:
            f.write(content.replace(".gitlab", self.output_folder))

    def apply_jobs_data(self, enabledJobs):
        self.apply_on_file(self.gitlab_ci_file, enabledJobs)
        for file in glob.glob(self.gitlab_folder + "/**/*.yml", recursive=True):
            self.apply_on_file(file, enabledJobs)


if __name__ == "__main__":
    extender = GitlabExtender(None)
    extender.run()
    extender.deps_graph.resolve_stage_dep()
    deps = extender.list_jobs_dependencies()
    with open("out.csv", "w") as f:
        content = "JobName,Dependencies"
        for key in deps:
            content += f"\n{key}," + ",".join(deps[key])
        f.write(content)
