import oyaml as yaml


class DepNode:
    """
    Base dependency graph node
    :name Job name
    :data Associated to the node usually boolean
    :children List of the node's children
    """
    def __init__(self, name, data, children, parent=None):
        if parent is None:
            parent = []
        self.name = name
        self.data = data
        self.children = children
        self.parent = parent


class DepGraph:
    def __init__(self, entrypoint=None):
        self.entrypoint = entrypoint
        if entrypoint is None:
            self.entrypoint = ".dynamic.yml"
        self.stage_list = []
        self.job_tags = {}
        self.init_graph()
        self.root = DepNode("StartNode", False, [])
        self.ghost_edges = {}
        self.job_lists = []
        self.seen_map = []
        self.debug = False

    def init_graph(self):
        """
        Setuo stage node of the dependency graph
        :return: (DepNode) The root of the graph
        """
        with open(self.entrypoint, "r") as f:
            yaml_content = yaml.load(f.read(), Loader=yaml.SafeLoader)
        self.stage_list = list(yaml_content["stages"])
        self.job_tags = {stage: [] for stage in self.stage_list}
        self.job_tags["no-stage"] = []
        self.job_tags["no-dep"] = []

    def find_node(self, node_name): # TODO: Slow because of seen map
        if not self.root:
            return None

        queue = [self.root]
        while queue:
            node = queue.pop(0)
            self.seen_map.append(node.name)
            if node.name == node_name:
                return node
            for child in node.children:
                if child.name not in self.seen_map:
                    queue.append(child)
        return None

    def propagate_node_state(self, node_name, new_state, reverse=False): # TODO: Slow because of seen map
        self.seen_map = []
        node = self.find_node(node_name)
        self.seen_map = []
        if node is not None:
            if not reverse:
                self.__propagate_node_state(node, new_state, 0)
            else:
                self.__propagate_parent_node_state(node,new_state, 0)

    def __propagate_node_state(self, node, new_state, distance):
        if node.name in self.seen_map:
            return
        if distance > 4:
            distance = 4
        if new_state:
            node.data = "activated_" + str(int(distance))
        else:
            node.data = new_state
        self.seen_map.append(node.name)
        for child in node.children:
            self.__propagate_node_state(child, new_state, distance + 0.5)

    def __propagate_parent_node_state(self, node, new_state, distance):
        if node.name in self.seen_map:
            return
        if distance > 4:
            distance = 4
        if new_state:
            node.data = "activated_" + str(int(distance))
        else:
            node.data = new_state
        self.seen_map.append(node.name)
        if not node.parent:
            return
        for child in node.parent:
            self.__propagate_parent_node_state(child, new_state, distance + 0.5)

    def __insert_node_after_dep(self, dep_nodes, new_node):
        for node in dep_nodes:
            self.__append_node_children(node, new_node)



    def __append_node_children(self, node, new_node):
        if new_node not in node.children:
            node.children.append(new_node)
        if node not in new_node.parent:
            new_node.parent.append(node)

    def __parse_dependencies(self, deps):
        if deps is None:
            return None
        for k,elem in enumerate(deps):
            if type(elem) == dict:
                if elem.get('job', None) is not None:
                    deps[k] = elem['job']
        return deps

    def append_node(self, job_name, stage, dependencies=[]):
        dependencies = self.__parse_dependencies(dependencies)

        if job_name[0] == ".":
            return
        if self.debug:
            print(f"Call to append_node with {job_name} {stage} {dependencies}")
            self.job_lists.append(job_name)
        new_node = DepNode(job_name, False, [])
        self.job_tags[stage].append(new_node)
        queue = [self.root, None]
        current_found_deps = []
        depth = 1
        while queue and dependencies:
            node = queue.pop(0)
            if node is not None:
                if node.name in dependencies:
                    current_found_deps.append(node)
                    dependencies.remove(node.name)
                if not dependencies:
                    self.__insert_node_after_dep(current_found_deps, new_node)
                    #self.__ghost_edge_resolve(new_node)
                    return
                else:
                    for child in node.children:
                        if child not in queue:
                            queue.append(child)
            else:
                depth += 1
                if queue:
                    queue.append(None)
                else:  # missing dependencies -> create ghost edge
                    for missing_dep in dependencies:
                        if self.ghost_edges.get(missing_dep, None) is None:
                            self.ghost_edges[missing_dep] = [new_node]
                        else:
                            self.ghost_edges[missing_dep].append(new_node)
                    break

        if dependencies is None:
            self.__insert_node_after_dep([self.root], new_node)
        elif not dependencies:
            self.job_tags["no-dep"].append((new_node, stage))

        #self.__ghost_edge_resolve(new_node)

    def __ghost_edge_resolve(self, new_node):
        if self.ghost_edges.get(new_node.name, None) is not None:
            for dep in self.ghost_edges[new_node.name]:
                self.__append_node_children(new_node, dep)
                self.__ghost_edge_resolve(dep)
            del self.ghost_edges[new_node.name]

    def resolve_stage_dep(self):
        #print([(n.name, s) for n, s in self.job_tags["no-dep"]])
        for new_node, stage in self.job_tags["no-dep"]:
            if stage == "no-stage":
                continue
            try:
                stage_index = self.stage_list.index(stage)
            except ValueError:
                print("Wrong stage name : ", stage)
                return
            if stage_index > 0:
                self.__insert_node_after_dep(self.job_tags[self.stage_list[stage_index - 1]], new_node)
            else:
                self.__append_node_children(self.root, new_node)
        del self.job_tags["no-dep"]

        for stage in self.job_tags:
            for node in self.job_tags[stage]:
                self.__ghost_edge_resolve(node)
        if self.debug:
            print("Unresolved ghost dependency : ", sum([len(elem[1]) for elem in self.ghost_edges.items()]))
            print(self.ghost_edges.keys())
            print(len(self.job_lists))

    def pipeline_jobs_to_run(self, needed_jobs_list):
        self.propagate_node_state("StartNode", False)
        for job in needed_jobs_list:
            self.propagate_node_state(job, True, True)
        queue = []
        nodes = []
        while queue:
            node = queue.pop(0)
            if node.data:
                nodes.append(node.name)
            for child in node.children:
                queue.append(child)
        return nodes

