import sys
import os
import argparse
from pathlib import Path
import OpenEXR
from PySide6.QtWidgets import QDialog, QTreeWidget, QVBoxLayout, QApplication, QLineEdit, QPushButton, QWidget, \
    QMainWindow


def gather_deps_from_nk_file(nuke_script):
    """
    Get all dependencies inside a nuke file based on allowed list of nodes.

    Args:
        nuke_script str: Path to nuke script.

    Returns:
        list: List of all paths in nuke file.
    """

    if "\\" in nuke_script:
        nuke_script = nuke_script.replace("\\", "/")

    nuke_file = open(nuke_script, "r", encoding="utf-8", errors="ignore")
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
            node_collector["type"] = line_s.replace(" ", "").strip(
                "{"
            )  # assumes it's before the {
            node_found = True

    dep_results_list = (
        []
    )  # glob paths to files or file collections that have an associated error or pass message

    for node in nodes:
        if ".gizmo" in node["type"] or check_node_disabled(node):
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
        # print(r"no file path in {} node : {}".format(node["type"], node.get("name", "unnamed")))
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


def process_files(nuke_file):

    if not nuke_file.exists():
        print("The target directory doesn't exist")
        return

    file_paths = gather_deps_from_nk_file(str(nuke_file))
    file_paths.sort(key=str.lower)

    return file_paths

class FindNestedAssets(QWidget):
    def __init__(self):
        super().__init__()

        self.tree_widget = QTreeWidget()
        self.tree_widget.setHeaderLabels(["Node Path", "Filepath"])

        self.input_filepath = QLineEdit("Path to Nuke File...")

        self.set_input = QPushButton("Set Input")

        layout = QVBoxLayout()
        layout.addWidget(self.input_filepath)
        layout.addWidget(self.set_input)
        layout.addWidget(self.tree_widget,3)

        self.setLayout(layout)

        self.set_input.clicked.connect(lambda: self.execute_nuke_search(Path(self.input_filepath.text())))

    def execute_nuke_search(self, input_path):
        file_names = process_files(input_path)
        print(f"These are the file names: " + str(file_names))

class MainWindow(QMainWindow):
    def __init__(self, widget):
        super().__init__()
        self.setWindowTitle("Nuke Asset Inspector")

        self.setCentralWidget(widget)

if __name__ == "__main__":

    parser = argparse.ArgumentParser()

    parser.add_argument("Read")
    parser.add_argument("-l", "--long", action="store_true")
    parser.add_argument("-m", "--metadata", action="store_true")
    args = parser.parse_args()

    # Get the Nuke script path input.
    nuke_file = Path(args.Read)

    # Get the list of full file path dependencies from the Nuke script.
    file_names = process_files(nuke_file)

    for file in file_names:
        print(os.path.basename(file) if not args.long else file)
    #
    #     # Begin metadata check.
        with OpenEXR.File(file) as infile:
            header = infile.header()
            print(header)

    app = QApplication(sys.argv)
    widget = FindNestedAssets()

    window = MainWindow(widget)
    window.resize(800, 600)
    window.show()

    print(f"Total dependencies: " + str(len(file_names)))

    sys.exit(app.exec())