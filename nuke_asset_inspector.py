import sys
import os
import argparse
from pathlib import Path
import OpenEXR
from PySide6.QtWidgets import (
    QDialog,
    QTreeWidget,
    QVBoxLayout,
    QApplication,
    QLineEdit,
    QPushButton,
    QWidget,
    QMainWindow,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QSpacerItem,
    QSizePolicy, QTreeWidgetItem,
)


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
    print(file_paths)

    return file_paths


class FindNestedAssets(QWidget):
    def __init__(self):
        super().__init__()

        main_layout = QVBoxLayout()

        # Nuke script input setup.
        self.input_label = QLabel("Nuke Script Input: ")
        self.input_filepath = QLineEdit()
        self.input_filepath.setPlaceholderText("")
        self.open_explorer_input = QPushButton("...")
        self.open_explorer_input.clicked.connect(
            lambda: self.open_explorer_dialog(True, self.input_filepath)
        )
        file_input_h_layout = QHBoxLayout()
        file_input_h_layout.addWidget(self.input_label)
        file_input_h_layout.addWidget(self.input_filepath)
        file_input_h_layout.addWidget(self.open_explorer_input)

        self.set_input = QPushButton("Set Input")
        self.set_input.clicked.connect(
            lambda: self.execute_nuke_search(self.input_filepath.text())
        )

        horizontal_spacer = QSpacerItem(
            40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum
        )
        # Tree Widget.
        self.tree_label = QLabel("Located Dependencies:")
        self.tree_widget = QTreeWidget()
        self.tree_widget.setHeaderLabels(["Filepath"])

        # Nuke script output setup.
        self.output_label = QLabel("Folder to Copy to: ")
        self.output_filepath = QLineEdit()
        self.output_filepath.setPlaceholderText("")
        self.open_explorer_output = QPushButton("...")
        self.open_explorer_output.clicked.connect(
            lambda: self.open_explorer_dialog(False, self.output_filepath)
        )
        file_output_h_layout = QHBoxLayout()
        file_output_h_layout.addWidget(self.output_label)
        file_output_h_layout.addWidget(self.output_filepath)
        file_output_h_layout.addWidget(self.open_explorer_output)

        self.open_explorer = QPushButton("Copy to Output Directory")
        # self.open_explorer.clicked.connect(lambda: self.open_explorer_dialog())

        main_layout.addLayout(file_input_h_layout)
        main_layout.addWidget(self.set_input)
        main_layout.addItem(horizontal_spacer)
        main_layout.addWidget(self.tree_label)
        main_layout.addWidget(self.tree_widget)
        main_layout.addItem(horizontal_spacer)
        main_layout.addLayout(file_output_h_layout)
        main_layout.addWidget(self.open_explorer)

        self.setLayout(main_layout)

    def execute_nuke_search(self, input_path):
        input_path = input_path.strip()
        if Path(input_path).is_file():
            file_names = process_files(Path(input_path))
            for file_name in file_names:
                self.tree_widget.addTopLevelItem(QTreeWidgetItem([file_name]))
        else:
            print("No file found.")

    def open_explorer_dialog(self, is_file: bool, line_edit: QLineEdit) -> None:
        path = (
            QFileDialog.getOpenFileName(
                self,
                "Open Explorer",
                str(Path(line_edit.text())),
                "Nuke Files (*.nk);;Text Files (*.txt);;All Files (*)",
            )[0]
            if is_file
            else QFileDialog.getExistingDirectory(self, "Select Copy Location")
        )

        if path:
            line_edit.setText(path)


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

    # for file in file_names:
    #     print(os.path.basename(file) if not args.long else file)
    #     #
    #     #     # Begin metadata check.
    #     with OpenEXR.File(file) as infile:
    #         header = infile.header()
    #         print(header)

    app = QApplication(sys.argv)
    widget = FindNestedAssets()

    window = MainWindow(widget)
    window.resize(800, 600)
    window.show()

    # print(f"Total dependencies: " + str(len(file_names)))

    sys.exit(app.exec())
