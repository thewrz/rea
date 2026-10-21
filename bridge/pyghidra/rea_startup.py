"""Ephemeral project import and the pre/post auto-analysis pipeline."""
import hmac
import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PROJECT_NAME = "rea"


@dataclass
class Workspace:
    """The ephemeral project and the single imported Program this bridge owns."""

    project: Any
    locator: Any
    program: Any
    consumer: Any

    def close(self):
        """Release the Program, close the project and delete every project file."""
        errors = []
        for step in (
            lambda: self.program.release(self.consumer),
            self.project.close,
            self._delete_project_files,
        ):
            try:
                step()
            except Exception as exception:
                errors.append(exception)
        if errors:
            raise RuntimeError(f"Ghidra project cleanup failed: {errors}") from errors[0]

    def _delete_project_files(self):
        shutil.rmtree(str(self.locator.getProjectDir()), ignore_errors=False)
        for marker in (self.locator.getMarkerFile(), self.locator.getProjectLockFile()):
            path = str(marker.getPath())
            if os.path.lexists(path):
                os.remove(path)


def start_ghidra(provider_version):
    import pyghidra

    install_dir = os.environ.get("GHIDRA_INSTALL_DIR")
    if not install_dir:
        raise RuntimeError("GHIDRA_INSTALL_DIR is required to start pyGhidra")
    pyghidra.start(install_dir=Path(install_dir))
    from ghidra.framework import Application

    version = str(Application.getApplicationVersion())
    if version != provider_version:
        raise RuntimeError("Ghidra provider version does not match the session")
    return version


def import_target(runtime_root, target_path, descriptor):
    """Import the target into a fresh project; the caller owns the returned Workspace."""
    import pyghidra
    from ghidra.util.task import TaskMonitor

    project_root = os.path.join(runtime_root, "project")
    os.makedirs(project_root, exist_ok=True)
    project = pyghidra.open_project(project_root, PROJECT_NAME, create=True)
    workspace = None
    try:
        builder = (
            pyghidra.program_loader()
            .project(project)
            .source(target_path)
            .projectFolderPath("/")
        )
        if descriptor.language_id is not None:
            builder = builder.language(descriptor.language_id)
        if descriptor.compiler_spec_id is not None:
            builder = builder.compiler(descriptor.compiler_spec_id)
        with builder.load() as results:
            results.save(TaskMonitor.DUMMY)
        program, consumer = pyghidra.consume_program(
            project, "/" + os.path.basename(target_path)
        )
        workspace = Workspace(project, project.getProjectLocator(), program, consumer)
        return workspace
    finally:
        if workspace is None:
            project.close()


def verify_imported_target(program, descriptor):
    """Echoing an expected digest is not import attestation; measure the imported bytes."""
    if program.getExecutableFormat() == "Raw Binary":
        raise RuntimeError(
            "The pyGhidra bridge does not prepare raw-binary imports; use the Java backend"
        )
    imported = program.getExecutableSHA256()
    if imported is None or not hmac.compare_digest(
        str(imported).lower().encode("utf-8"), descriptor.target_sha256.encode("utf-8")
    ):
        raise RuntimeError("Ghidra imported-byte digest does not match the admitted target")


def _disable_analyzers(program, names):
    import pyghidra
    from ghidra.app.plugin.core.analysis import AutoAnalysisManager

    manager = AutoAnalysisManager.getAnalysisManager(program)
    options = pyghidra.analysis_properties(program)
    for name in names:
        if manager.getAnalyzer(name) is None or not options.contains(name):
            raise ValueError(f"Unknown Ghidra analyzer for this program: {name}")
    with pyghidra.transaction(program, "REA analyzer options"):
        for name in names:
            options.setBoolean(name, False)
    for name in names:
        if options.getBoolean(name, True):
            raise RuntimeError(f"Ghidra analyzer remained enabled: {name}")


def analyze_program(program, monitor, descriptor):
    """Seeds, then analyzer options, then auto-analysis, then the post-analysis repairs."""
    import pyghidra

    if descriptor.seed_paths:
        from rea_analysis_seeds import apply_seeds

        apply_seeds(program, monitor, descriptor.seed_paths[0])
    if descriptor.disabled_analyzers:
        _disable_analyzers(program, descriptor.disabled_analyzers)
    print("REA pyGhidra: running auto-analysis", file=sys.stderr)
    pyghidra.analyze(program)
    from rea_analysis_no_return import fix_no_return

    fix_no_return(program, monitor)
    if descriptor.mips_soft_float:
        from rea_analysis_mips_soft_float import apply_soft_float

        apply_soft_float(program, monitor)
