"""Vulnerability audit on top of a successful ``/resolve`` response.

Given the ``resolved`` versions and ``dependency_graph`` edges returned by
``POST /resolve`` plus a local list of advisories (each with an affected
PEP 440 specifier), the audit:

1. validates that every graph edge is well formed and consistent with the
   resolved versions (versions must parse as PEP 440, endpoints must exist,
   the root node may only appear as a source with an empty version, ...);
2. matches advisories against the *resolved* version of their package;
3. for each hit, enumerates **every shortest path** from ``<root>`` to the
   package.  Hits that cannot be reached from ``<root>`` are reported as
   ``orphaned`` instead.

The graph may contain cycles or diamonds.  Shortest paths are enumerated with
a breadth-first predecessor frontier, which terminates on any finite graph --
cycles never cause infinite traversal -- and each enumerated simple path is
itself naturally node-unique.  Path lists are sorted by their node sequences,
so identical input always yields identical output.
"""

from __future__ import annotations

from typing import Any, Optional

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from .resolver import ROOT, ResolutionInputError


def _node(name: str, version: str) -> dict[str, str]:
    return {"name": name, "version": version}


def validate_audit_input(
    resolved: dict[str, str],
    dependency_graph: list[dict[str, str]],
    advisories: list[Any],
) -> tuple[
    dict[str, tuple[str, Version]],
    dict[str, set[str]],
    list[tuple[str, str, SpecifierSet]],
]:
    """Parse and semantically validate an audit request.

    Returns ``(packages, adjacency, parsed_advisories)`` where

    * ``packages`` maps canonical name -> ``(raw resolved version, Version)``;
    * ``adjacency`` maps a canonical source package (or :data:`ROOT`) to the
      set of canonical targets reached by one graph edge;
    * ``parsed_advisories`` is a list of
      ``(canonical package, id, SpecifierSet)`` tuples in request order.

    Every detected problem is accumulated into one
    :class:`ResolutionInputError` (mapped to HTTP 400), mirroring how
    :func:`app.resolver.parse_index` reports index errors.
    """
    errors: list[str] = []
    packages: dict[str, tuple[str, Version]] = {}
    for package in sorted(resolved):
        raw_version = resolved[package]
        try:
            parsed = Version(raw_version)
        except InvalidVersion as exc:
            errors.append(
                f"resolved version for {package!r}: {raw_version!r} is not PEP 440: {exc}"
            )
            continue
        canonical = canonicalize_name(package)
        if canonical in packages:
            errors.append(
                f"resolved package {package!r}: duplicates {canonical!r} after name normalization"
            )
            continue
        packages[canonical] = (raw_version, parsed)

    adjacency: dict[str, set[str]] = {ROOT: set()}
    for index, edge in enumerate(dependency_graph):
        origin = f"dependency_graph[{index}]"
        source = edge["source"]
        target = edge["target"]
        source_version = edge["source_version"]
        target_version = edge["target_version"]

        source_canonical: Optional[str]
        if source == ROOT:
            source_canonical = ROOT
            if source_version != "":
                errors.append(
                    f"{origin}: {ROOT!r} edge must carry an empty source_version,"
                    f" got {source_version!r}"
                )
        else:
            source_canonical = canonicalize_name(source)
            if source_canonical not in packages:
                errors.append(
                    f"{origin}: dangling edge references source package "
                    f"{source!r} absent from resolved"
                )
            elif packages[source_canonical][0] != source_version:
                errors.append(
                    f"{origin}: edge source version {source_version!r} for "
                    f"{source!r} does not match resolved version "
                    f"{packages[source_canonical][0]!r}"
                )

        target_canonical: Optional[str]
        if target == ROOT:
            target_canonical = None
            errors.append(f"{origin}: {ROOT!r} may only appear as an edge source")
        else:
            target_canonical = canonicalize_name(target)
        if target_canonical is not None and target_canonical not in packages:
            errors.append(
                f"{origin}: dangling edge references target package "
                f"{target!r} absent from resolved"
            )
        elif target_canonical is not None:
            if packages[target_canonical][0] != target_version:
                errors.append(
                    f"{origin}: edge target version {target_version!r} for "
                    f"{target!r} does not match resolved version "
                    f"{packages[target_canonical][0]!r}"
                )
            if source_canonical is not None:
                adjacency.setdefault(source_canonical, set()).add(target_canonical)

    parsed_advisories: list[tuple[str, str, SpecifierSet]] = []
    for index, advisory in enumerate(advisories):
        origin = f"advisories[{index}]"
        advisory_id = advisory.get("id")
        package = advisory.get("package")
        affected = advisory.get("affected", "")
        if not isinstance(advisory_id, str) or not advisory_id:
            errors.append(f"{origin}: id must be a non-empty string")
            continue
        if not isinstance(package, str) or not package:
            errors.append(f"{origin} ({advisory_id!r}): package must be a non-empty string")
            continue
        if not isinstance(affected, str):
            errors.append(
                f"{origin} ({advisory_id!r}): affected must be a PEP 440 specifier string"
            )
            continue
        try:
            specifier = SpecifierSet(affected)
            # SpecifierSet accepts a malformed version token inside an
            # otherwise valid operator lazily; force the parse here.
            specifier.contains("0", prereleases=True)
        except (InvalidSpecifier, InvalidVersion, ValueError) as exc:
            errors.append(
                f"{origin} ({advisory_id!r}): invalid PEP 440 specifier "
                f"{affected!r}: {exc}"
            )
            continue
        parsed_advisories.append((canonicalize_name(package), advisory_id, specifier))

    if errors:
        raise ResolutionInputError("; ".join(errors))
    return packages, adjacency, parsed_advisories


def _all_shortest_paths(
    adjacency: dict[str, set[str]], target: str
) -> list[list[str]]:
    """Every shortest node sequence from :data:`ROOT` to ``target``.

    Breadth-first expansion keeps, for each reached node, all predecessors
    that reach it in the minimum number of hops.  Cycles are naturally
    excluded: only nodes discovered at strictly lower levels are kept, and
    the BFS frontier itself never revisits a node, so traversal is finite on
    any graph with cycles or diamonds.
    """
    predecessors: dict[str, set[str]] = {}
    frontier = [ROOT]
    seen = {ROOT}
    found = target == ROOT
    while frontier and not found:
        next_frontier: list[str] = []
        next_seen: set[str] = set()
        for node in frontier:
            for neighbour in adjacency.get(node, ()):  # edges out of ROOT/known nodes only
                if neighbour in seen:
                    continue
                predecessors.setdefault(neighbour, set()).add(node)
                if neighbour not in next_seen:
                    next_seen.add(neighbour)
                    next_frontier.append(neighbour)
        seen |= next_seen
        frontier = next_frontier
        found = target in seen

    if not found:
        return []

    paths: list[list[str]] = []

    def assemble(node: str, tail: list[str]) -> None:
        if node == ROOT:
            paths.append([ROOT, *reversed(tail)])
            return
        for predecessor in sorted(predecessors.get(node, ())):
            assemble(predecessor, tail + [node])

    assemble(target, [])
    return sorted(paths, key=lambda sequence: tuple(sequence))


def audit_vulnerabilities(
    resolved: dict[str, str],
    dependency_graph: list[dict[str, str]],
    advisories: list[Any],
) -> dict[str, list[dict[str, Any]]]:
    """Validate input, match advisories and render the audit response body."""
    packages, adjacency, parsed_advisories = validate_audit_input(
        resolved, dependency_graph, advisories
    )

    findings: list[tuple[str, int, dict[str, Any]]] = []
    orphaned: list[tuple[str, int, dict[str, Any]]] = []

    for order, (package, advisory_id, specifier) in enumerate(parsed_advisories):
        if package not in packages:
            # Advisories for packages outside the resolution do not hit.
            continue
        raw_version, parsed_version = packages[package]
        if not specifier.contains(parsed_version, prereleases=True):
            continue
        hit = {
            "advisory": advisories[order],
            "package": package,
            "version": raw_version,
        }
        paths = [
            [
                _node(ROOT, "")
                if name == ROOT
                else _node(name, packages[name][0])
                for name in sequence
            ]
            for sequence in _all_shortest_paths(adjacency, package)
        ]
        if paths:
            hit["paths"] = paths
            findings.append(((package, advisory_id), order, hit))
        else:
            orphaned.append(((package, advisory_id), order, hit))

    findings.sort(key=lambda item: (item[0], item[1]))
    orphaned.sort(key=lambda item: (item[0], item[1]))
    return {
        "findings": [entry for _key, _order, entry in findings],
        "orphaned": [entry for _key, _order, entry in orphaned],
    }
