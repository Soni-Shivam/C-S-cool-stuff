from __future__ import annotations

from drishti.contracts.static_report import CallPath
from drishti.m2_static.decompile import MAX_DECOMPILED_METHODS, _path_indexes, _selected_signatures


def _path(index: int) -> CallPath:
    entry = f"Lcom/example/C{index};->onCreate"
    helper = f"Lcom/example/C{index};->check"
    sink = "Landroid/content/pm/PackageManager;->getInstalledPackages"
    return CallPath(
        sink_id="pkg_query",
        sink_signature=sink,
        path=(entry, helper, sink),
        entrypoint=entry,
        entrypoint_kind="lifecycle",
        reachable_from_lifecycle=True,
    )


def test_selection_is_sink_reachable_unique_and_bounded() -> None:
    paths = tuple(_path(index) for index in range(20))
    selected = _selected_signatures(paths)
    assert len(selected) == MAX_DECOMPILED_METHODS
    assert all("PackageManager" not in signature for signature in selected)
    assert len(selected) == len(set(selected))


def test_method_records_every_call_path_that_uses_it() -> None:
    path = _path(1)
    indexes = _path_indexes((path, path))
    assert indexes[path.entrypoint] == (0, 1)
