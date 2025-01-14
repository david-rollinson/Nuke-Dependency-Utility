import sys
import os
import argparse
import subprocess
from importlib.metadata import metadata
from pathlib import Path
import OpenEXR
from PySide6.QtWidgets import (
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
    QSizePolicy,
    QTreeWidgetItem, QDialog, QDialogButtonBox,
)
from PySide6.QtCore import Qt, Signal


def gather_deps_from_nk_file(nuke_script: str) -> list[str]:
    """
    Get all dependencies inside a nuke file based on allowed list of nodes.

    Args:
        nuke_script str: Path to nuke script.

    Returns:
        list: List of all paths in nuke file.
    """

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
        print(node)
        if ".gizmo" in node["type"] or check_node_disabled(node):
            pass
        else:
            result = check_nuke_node_contents(node)
            if result and result not in dep_results_list:
                dep_results_list.append(result)

    return dep_results_list


def check_nuke_node_contents(node: dict[str, str]) -> str:
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


def check_node_disabled(node: dict[str, str]) -> bool:
    """
    Checks current node for disabled key status, returning true if 'disabled' is found.
    Args:
        node: Dict of nuke key value pairs.

    Returns:
        bool: Disabled key status at current node. Only returns true - Nuke doesn't store a 'disabled: false' pair.
    """
    disabled_keys = [
        "disable",
    ]

    for key in disabled_keys:
        disabled = node.get(key)

    return disabled


def process_files(nuke_file: Path) -> list[str]:
    """
    Checks if an input file path exists, then runs the dependency gather process if true.
    Args:
        Path: object containing the nuke script file path.

    Returns:
        list[str]: Containing valid script paths.
    """
    if not nuke_file.exists():
        print("The target directory doesn't exist")
        return

    file_paths = gather_deps_from_nk_file(str(nuke_file))
    file_paths.sort(key=str.lower)
    print(file_paths)

    return file_paths


def find_nested_assets_CLI():
    """
    Runs the Nuke Dependency Check in CLI format.

    Using this function requires the script to be run in a Terminal, taking the positional Read argument and the optional -l and -m arguments. `-l` returns the absolute path, `-m` returns any .exr metadata found in scripts.
    """
    parser = argparse.ArgumentParser()

    parser.add_argument("Read")
    parser.add_argument("-l", "--long", action="store_true")
    parser.add_argument("-m", "--metadata", action="store_true")
    args = parser.parse_args()

    # Get the Nuke script path input.
    nuke_file = Path(args.Read)

    # Get the list of full file path dependencies from the Nuke script.
    file_names = process_files(nuke_file)
    print(f"Total dependencies: " + str(len(file_names)))


class FindNestedAssets(QWidget):
    def __init__(self):
        super().__init__()

        main_layout = QVBoxLayout()

        # Dynamically set launch command for found .hip files in metadata.
        self.launch_path = ""
        self.launch_cmd = "cmd /c echo Opening"

        # Set global cut in for frames.
        self.cut_in = "1001"

        # Nuke script input setup.
        self.input_label = QLabel("Nuke Script Input: ")
        self.input_filepath = QLineEdit()
        self.input_filepath.setPlaceholderText("")

        self.open_explorer_input = QPushButton("...")
        self.open_explorer_input.clicked.connect(
            lambda: self.open_explorer_dialog(True, self.input_filepath)
        )
        self.launch_nk_button = QPushButton("Launch")
        self.launch_nk_button.clicked.connect(
            lambda: self.launch_nk(self.input_filepath.text())
        )

        file_input_h_layout = QHBoxLayout()
        file_input_h_layout.addWidget(self.input_label)
        file_input_h_layout.addWidget(self.input_filepath)
        file_input_h_layout.addWidget(self.open_explorer_input)
        file_input_h_layout.addWidget(self.launch_nk_button)

        self.set_input = QPushButton("Search for Dependencies")
        self.set_input.clicked.connect(
            lambda: self.execute_nuke_search(self.input_filepath.text())
        )

        horizontal_spacer = QSpacerItem(
            40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum
        )

        # Tree Widget.
        self.tree_widget = QTreeWidget()
        self.tree_widget.setHeaderLabels(["Filepath"])
        self.metadata_button = QPushButton("Gather EXR Metadata")
        self.metadata_button.clicked.connect(
            lambda: self.extract_metadata(self.tree_widget)
        )

        # Launch the file on double clicked.
        self.tree_widget.itemDoubleClicked.connect(self.on_double_click)

        # Tree Widget titlebar.
        tree_title = QHBoxLayout()
        self.tree_label = QLabel("Located Dependencies:")
        self.clear_items = QPushButton("Clear")
        self.clear_items.clicked.connect(lambda: self.tree_widget.clear())
        self.tree_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        self.clear_items.setSizePolicy(QSizePolicy.Minimum, QSizePolicy.Minimum)

        tree_title.addWidget(self.tree_label)
        tree_title.addWidget(self.clear_items)

        self.open_files = QPushButton("Open Selected")
        self.open_files.clicked.connect(lambda: self.launch_selected(self.tree_widget))
        self.advanced_options = QPushButton("Advanced...")
        self.advanced_options.clicked.connect(lambda: self.advanced_dialog())
        self.open_files.setMaximumWidth(self.width() // 3)
        self.open_files.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        self.advanced_options.setMaximumWidth(self.width() // 3)
        self.advanced_options.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        self.h_spacer = QSpacerItem(1, 1, QSizePolicy.Expanding, QSizePolicy.Minimum)

        open_context_h_layout = QHBoxLayout()
        open_context_h_layout.addItem(self.h_spacer)
        open_context_h_layout.addWidget(self.open_files)
        open_context_h_layout.addWidget(self.advanced_options)

        # Nuke script output setup.
        # self.output_label = QLabel("Folder to Copy to: ")
        # self.output_filepath = QLineEdit()
        # self.output_filepath.setPlaceholderText("")
        # self.open_explorer_output = QPushButton("...")
        # self.open_explorer_output.clicked.connect(
        #     lambda: self.open_explorer_dialog(False, self.output_filepath)
        # )
        # file_output_h_layout = QHBoxLayout()
        # file_output_h_layout.addWidget(self.output_label)
        # file_output_h_layout.addWidget(self.output_filepath)
        # file_output_h_layout.addWidget(self.open_explorer_output)

        # self.open_explorer = QPushButton("Copy Dependencies to Output Directory")
        # self.open_explorer.clicked.connect(lambda: self.open_explorer_dialog())

        main_layout.addLayout(file_input_h_layout)
        main_layout.addWidget(self.set_input)
        main_layout.addItem(horizontal_spacer)
        main_layout.addLayout(tree_title)
        main_layout.addWidget(self.tree_widget)
        main_layout.addWidget(self.metadata_button)
        main_layout.addLayout(open_context_h_layout)
        # main_layout.addItem(horizontal_spacer)
        # main_layout.addLayout(file_output_h_layout)
        # main_layout.addWidget(self.open_explorer)

        self.setLayout(main_layout)

    def execute_nuke_search(self, input_path: str) -> None:
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

    def extract_metadata(self, tree_widget: QTreeWidget) -> None:
        for i in range(tree_widget.topLevelItemCount()):
            top_item = tree_widget.topLevelItem(i)
            with OpenEXR.File(top_item.text(0)) as infile:
                header = infile.header()
                path_keys = {
                    key: value
                    for key, value in header.items()
                    if "File" in key or "file" in key or "Path" in key or "path" in key
                }
                for key, value in path_keys.items():
                    metadata_child = QTreeWidgetItem()
                    metadata_child.setData(0, Qt.UserRole, {key: value})
                    metadata_child.setText(0, str(f"{key}: {value}"))
                    top_item.addChild(metadata_child)
                    metadata_child.setCheckState(0, Qt.Unchecked)

            # Set parent to expanded.
            top_item.setExpanded(True)

    def launch_selected(self, tree_widget: QTreeWidget) -> None:
        for i in range(tree_widget.topLevelItemCount()):
            current_parent = tree_widget.topLevelItem(i)
            for j in range(current_parent.childCount()):
                current_child = current_parent.child(j)
                if result := current_child.checkState(0) == Qt.Checked:
                    print(f"{current_child.text(0)} is set to {result}")
                    child_data = current_child.data(0, Qt.UserRole)
                    self.launch_path = next(iter(child_data.values()))
                    print(f"Launch command: {self.launch_cmd} {self.launch_path}")
                    # subprocess.Popen(f"{self.launch_cmd} {self.launch_path}") # Placeholder.

    def launch_nk(self, nuke_file: str) -> None:
        subprocess.Popen(f"cmd /c {nuke_file}")

    def on_double_click(self, item, column):
        if item.parent() is None:
            file_path = item.text(column)
            print(f"{file_path} was double clicked.")

            file_path = file_path.replace("####", self.cut_in).replace("%04d", self.cut_in)
            subprocess.Popen(f"cmd /c {file_path}")

    def advanced_dialog(self) -> None:
        """
        Launches an 'Advanced' dialog for user changes to the .hip file launch command.
        """
        dlg = AdvancedDialog(self)
        dlg.setMinimumWidth(500)

        # Connect the parent slot to child signal, to update the .hip file launch command.
        dlg.launch_cmd_changed.connect(self.update_widget)
        dlg.exec()

    def update_widget(self, advanced_cmd) -> None:
        """
        Assigns the hip file launch command signal from the child 'Advanced' dialog to the parent's launch command. Prints changes to the console.
        """
        print(f"Advanced dialog has updated the launch command from: `{self.launch_cmd}` to: `{advanced_cmd}`.")
        self.launch_cmd = advanced_cmd


class AdvancedDialog(QDialog):
    """
    A dialog for configuring advanced launch settings.

    This dialog allows the user to input/edit a custom launch command via a QLineEdit. On accept, the custom command is sent back to the parent QWidget to override its default launch command.

    Methods:
        apply_launch_cmd_edit():
            Emits str 'launch command' inside the QLineEdit as a signal to the parent's slot.
    """

    launch_cmd_changed = Signal(str)

    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowTitle("Advanced Options")

        # Inline dialog label and user input.
        self.cmd_label_open = QLabel("Launch Command: `")
        self.command_edit = QLineEdit()
        self.command_edit.setText(f"{parent.launch_cmd}")
        self.command_edit.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.filepath_edit = QLineEdit()
        self.filepath_edit.setText(f"{parent.launch_path}" if parent.launch_path else "<FILEPATH>")
        self.filepath_edit.setFixedSize(85, 20)
        self.filepath_edit.setReadOnly(True)
        self.cmd_label_close = QLabel("`")

        # Layout for above label and inputs.
        self.h_layout = QHBoxLayout()
        self.h_layout.addWidget(self.cmd_label_open)
        self.h_layout.addWidget(self.command_edit)
        self.h_layout.addWidget(self.filepath_edit)
        self.h_layout.addWidget(self.cmd_label_close)

        # Button layout.
        dialog_buttons = QDialogButtonBox.Apply | QDialogButtonBox.Discard
        self.buttonBox = QDialogButtonBox(dialog_buttons)
        # Connect actions to dialog buttons.
        self.buttonBox.button(dialog_buttons.Apply).clicked.connect(lambda: self.apply_launch_cmd_edit())
        self.buttonBox.button(dialog_buttons.Discard).clicked.connect(self.reject)

        self.main_layout = QVBoxLayout()
        self.main_layout.addLayout(self.h_layout)
        self.main_layout.addWidget(self.buttonBox)
        self.setLayout(self.main_layout)

        # if ok, set parent cmd to dialog input. if discard, close dialog.
    def apply_launch_cmd_edit(self) -> None:
        """
        Emits str 'launch command' from dialog QLineEdit as a signal to the parent widget's slot.
        """
        self.launch_cmd_changed.emit(self.command_edit.text())
        self.accept()

class MainWindow(QMainWindow):
    def __init__(self, widget):
        super().__init__()
        self.setWindowTitle("Nuke Dependency Utility | QC")
        self.setCentralWidget(widget)


if __name__ == "__main__":

    # find_nested_assets_CLI()

    app = QApplication(sys.argv)
    widget = FindNestedAssets()

    window = MainWindow(widget)
    window.resize(800, 600)
    window.show()

    sys.exit(app.exec())

    # TODO: Launch associated hip file paths.
    # associated rez command: jfenv houdini -c "houdini -n <PATHTOHIP.hip>" --patch houdini-19.5.605 -v
    # TODO: Launch frame sequence.
