"""Bounded, deterministic call-graph traversal primitives."""

from __future__ import annotations

from collections import deque

import networkx as nx  # type: ignore[import-untyped]

from drishti.contracts.static_report import CallPath


def backward_paths(
    graph: nx.DiGraph,
    *,
    sink: str,
    entrypoints: dict[str, str],
    max_depth: int = 6,
    max_paths: int = 5,
) -> tuple[CallPath, ...]:
    """Find shortest, distinct lifecycle-entrypoint paths terminating at one sink."""
    if sink not in graph:
        return ()
    queue: deque[tuple[str, tuple[str, ...]]] = deque([(sink, (sink,))])
    found: list[CallPath] = []
    seen_depth: dict[str, int] = {sink: 0}
    while queue and len(found) < max_paths:
        node, reversed_path = queue.popleft()
        depth = len(reversed_path) - 1
        if node in entrypoints:
            path = tuple(reversed(reversed_path))
            found.append(
                CallPath(
                    sink_id=sink,
                    sink_signature=sink,
                    path=path,
                    entrypoint=node,
                    entrypoint_kind=entrypoints[node],
                    reachable_from_lifecycle=True,
                )
            )
            continue
        if depth >= max_depth:
            continue
        for caller in sorted(graph.predecessors(node)):
            next_depth = depth + 1
            if next_depth > seen_depth.get(caller, max_depth + 1):
                continue
            seen_depth[caller] = next_depth
            queue.append((caller, (*reversed_path, caller)))
    return tuple(found)
