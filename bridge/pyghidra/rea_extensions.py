"""Session-owned Ghidra analysis extensions; algorithms stay behind each adapter ABI."""
import hashlib
import json
import os
import stat

from rea_session import exception_label

MAX_EXTENSION_BYTES = 8 * 1024 * 1024
REGISTERED_ABI = {
    "nativeaot": ("rea.extensions.nativeaot.NativeAotExtension", 1),
}


def _read_private_artifact(path):
    if not os.path.isabs(path):
        raise ValueError(f"Invalid private extension artifact: {path}")
    status = os.lstat(path)
    if not stat.S_ISREG(status.st_mode) or status.st_size > MAX_EXTENSION_BYTES:
        raise ValueError(f"Invalid private extension artifact: {path}")
    with open(path, "rb") as handle:
        return handle.read()


def _to_dict(response, what):
    from com.google.gson import JsonObject

    if not isinstance(response, JsonObject):
        raise ValueError(what)
    return json.loads(str(response.toString()))


def _failure_report(report, exception):
    reason = f"Extension loading/analysis failed: {exception_label(exception)}"
    cause = getattr(exception, "getCause", lambda: None)()
    if cause is not None:
        reason += f"; caused by {cause}"
    report.update(
        status="failed", reason=reason, result={"loader_failure": reason}
    )


class ExtensionHost:
    def __init__(self):
        self._loaded = []
        self._reports = []

    def analyze(self, descriptors, program, monitor):
        for descriptor in descriptors:
            report = {"id": descriptor["id"], "sha256": descriptor["sha256"]}
            try:
                loader, instance = self._load(descriptor, program, monitor, report)
                self._loaded.append((loader, instance, descriptor["sha256"]))
            except Exception as exception:
                _failure_report(report, self._unwrap(exception))
            self._reports.append(report)

    @staticmethod
    def _unwrap(exception):
        from java.lang.reflect import InvocationTargetException

        if isinstance(exception, InvocationTargetException):
            return exception.getCause()
        return exception

    def _load(self, descriptor, program, monitor, report):
        import jpype
        from ghidra.program.model.listing import Program
        from ghidra.util.task import TaskMonitor
        from java.io import File
        from java.lang import Class
        from java.net import URL, URLClassLoader

        entry = descriptor["entry_class"]
        if REGISTERED_ABI.get(descriptor["id"]) != (entry, descriptor["integration_api"]):
            raise ValueError(f"Unregistered Ghidra extension ABI: {descriptor['id']}")
        path = descriptor["path"]
        data = _read_private_artifact(path)
        if hashlib.sha256(data).hexdigest() != descriptor["sha256"]:
            raise ValueError(f"Private extension digest mismatch: {descriptor['id']}")
        urls = jpype.JArray(URL)([File(path).toURI().toURL()])
        loader = URLClassLoader(urls, Program.class_.getClassLoader())
        try:
            extension = Class.forName(entry, True, loader)
            instance = extension.getConstructor().newInstance()
            method = extension.getMethod("analyze", Program.class_, TaskMonitor.class_)
            response = method.invoke(instance, program, monitor)
            result = _to_dict(response, f"Invalid Ghidra extension result: {descriptor['id']}")
            report.update(status=result["status"], reason=result["reason"], result=result)
            return loader, instance
        except BaseException:
            loader.close()
            raise

    def reports(self):
        return json.loads(json.dumps(self._reports))

    def inspect_image(self):
        summaries = []
        for _, instance, sha256 in self._loaded:
            summary = _to_dict(
                instance.getClass().getMethod("inspectImage").invoke(instance),
                "Invalid extension image summary",
            )
            summary["analysis_artifact_sha256"] = sha256
            summaries.append(summary)
        return summaries

    def inspect_data_type(self, program, data_type, address, monitor):
        """The first extension's type metadata, or None when no extension describes the type."""
        from ghidra.program.model.address import Address
        from ghidra.program.model.data import DataType
        from ghidra.program.model.listing import Program
        from ghidra.util.task import TaskMonitor
        from java.lang.reflect import InvocationTargetException

        for _, instance, _ in self._loaded:
            method = instance.getClass().getMethod(
                "inspectDataType", Program.class_, DataType.class_, Address.class_, TaskMonitor.class_
            )
            try:
                response = method.invoke(instance, program, data_type, address, monitor)
            except InvocationTargetException as exception:
                cause = exception.getCause()
                if "CancelledException" in str(cause.getClass().getName()):
                    raise cause from exception
                raise RuntimeError(f"Ghidra extension type inspection failed: {cause}") from exception
            if response is not None:
                return _to_dict(response, "Invalid extension type metadata result")
        return None

    def close(self):
        failure = None
        loaded, self._loaded = self._loaded, []
        for loader, _, _ in loaded:
            try:
                loader.close()
            except Exception as exception:
                failure = failure or exception
        if failure is not None:
            raise failure
