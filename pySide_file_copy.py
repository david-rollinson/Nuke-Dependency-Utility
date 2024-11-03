import os
import argparse
from copyreg import Copy


def gather_deps_from_nk_file():
    """
    Get all dependencies inside a nuke file based on allowed list of nodes.

    Args:
        nuke_filepath str: Path to nuke script.

    Returns:
        list: List of all paths in nuke file.
    """
    nuke_filepath = r"/Users/davidrollinson/Documents/Development/Python/pySide_file_copy/nuke_example_file.nk"

    if "\\" in nuke_filepath:
        nuke_filepath = nuke_filepath.replace("\\", "/")

    nuke_file = open(nuke_filepath, "r", encoding="utf-8", errors="ignore")
    # file_path_open = "file "
    allowed_read_nodes = [
        "Read{",
        "Camera2{",  # this needs a Camera3 to work on nuke 13.
        "DeepRead{",
        "ReadGeo2{",
        "Root{",
        "Camera3{",
        "Write{",
    ]
    closed_node = "}\n"

    node_found = False
    nodes = []
    node_collector = {}
    # this loop attempts to convert the allowed nodes into a dict and stores it in a list
    i = 1
    for line in nuke_file:
        i += 1
        line_s = line.strip()  # line stripped
        line_s_w = line_s.replace(" ", "")  # line stripped without spaces

        if node_found:
            # reading line within a node
            if line.replace(" ", "") == closed_node:
                # if } end node collection
                node_found = False
                nodes.append(node_collector)
                node_collector = {}
            else:
                # assumes line within a node is always key{space}value and split at the first space
                line_split = line_s.split(" ")
                node_collector[line_split[0]] = " ".join(line_split[1:])

        if line_s_w in allowed_read_nodes or line_s_w.endswith(".gizmo{"):
            # assumes any node in allowed read nodes is a node we can get a "file" from
            node_collector["jf_type"] = line_s.replace(" ", "").strip(
                "{"
            )  # assumes its before the {
            node_found = True

    dep_results_list = (
        []
    )  # glob paths to files or file collections that have an asociated error or pass message

    for node in nodes:
        if ".gizmo" in node["jf_type"] or check_node_disabled(node):
            pass
        else:
            result = check_nuke_node_contents(node)
            if result and result not in dep_results_list:
                dep_results_list.append(result)

    return dep_results_list


def check_nuke_node_contents(node):
    """
    Checks a dict based on a nuke node for files and then checks files exist in a desired root.
    Args:
        node: Dict of nuke key value pairs.

    Returns:
        str: Path of media.
    """
    file_keys = [
        "file",
        # "customOCIOConfigPath"
    ]

    for key in file_keys:
        file_path = node.get(key)
        if file_path:
            break
    if not file_path:
        # logging.info("no file path in {} node : {}".format(node["jf_type"], node.get("name", "unnamed")))
        return

    file_path = file_path.replace('"', "")
    file_path = file_path.replace(os.sep, "/")

    return file_path


def check_node_disabled(node):
    disabled_keys = [
        "disable",
    ]

    for key in disabled_keys:
        disabled = node.get(key)

    return disabled


file_names = [os.path.basename(dep) for dep in gather_deps_from_nk_file()]
file_names.sort(key=str.lower)

for file_name in file_names:
    print(file_name)

print(len(file_names))
