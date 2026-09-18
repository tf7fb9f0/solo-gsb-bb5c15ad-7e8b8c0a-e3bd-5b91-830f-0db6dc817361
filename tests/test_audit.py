"""End-to-end tests for POST /audit/vulnerabilities."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

DIAMOND_RESOLVED = {
    "app": "1.0",
    "left": "1.0",
    "right": "1.0",
    "shared": "1.5",
}
DIAMOND_GRAPH = [
    {"source": "<root>", "source_version": "", "target": "app", "target_version": "1.0"},
    {"source": "app", "source_version": "1.0", "target": "left", "target_version": "1.0"},
    {"source": "app", "source_version": "1.0", "target": "right", "target_version": "1.0"},
    {"source": "left", "source_version": "1.0", "target": "shared", "target_version": "1.5"},
    {"source": "right", "source_version": "1.0", "target": "shared", "target_version": "1.5"},
]


def _audit(**payload):
    response = client.post("/audit/vulnerabilities", json=payload)
    return response.status_code, response.json()


def _names(paths):
    return [[node["name"] for node in path] for path in paths]


def test_diamond_reports_every_shortest_path_sorted():
    status, body = _audit(
        resolved=DIAMOND_RESOLVED,
        dependency_graph=DIAMOND_GRAPH,
        advisories=[
            {"id": "GHSA-shared", "package": "shared", "affected": "<2.0"},
            {"id": "GHSA-fixed", "package": "shared", "affected": ">=2.0"},
            {"id": "GHSA-app", "package": "app", "affected": ""},
        ],
    )
    assert status == 200
    assert body["orphaned"] == []
    findings = body["findings"]
    # Sorted by (package, advisory id): app before shared; only matching
    # advisories are present (GHSA-fixed excluded).
    assert [entry["advisory"]["id"] for entry in findings] == [
        "GHSA-app",
        "GHSA-shared",
    ]

    app_hit, shared_hit = findings
    assert app_hit["package"] == "app"
    assert app_hit["version"] == "1.0"
    assert _names(app_hit["paths"]) == [["<root>", "app"]]

    assert shared_hit["package"] == "shared"
    assert shared_hit["version"] == "1.5"
    assert _names(shared_hit["paths"]) == [
        ["<root>", "app", "left", "shared"],
        ["<root>", "app", "right", "shared"],
    ]
    # Every node carries the resolved version.
    for path in shared_hit["paths"]:
        for node in path[1:]:
            assert node["version"] == DIAMOND_RESOLVED[node["name"]]
    assert shared_hit["paths"][0][0] == {"name": "<root>", "version": ""}


def test_paths_are_node_unique_and_cycles_do_not_loop_forever():
    # a <-> b form a cycle; the shortest path to b must be the direct one,
    # reported once even though b also points back at a.
    resolved = {"a": "1.0", "b": "1.0"}
    graph = [
        {"source": "<root>", "source_version": "", "target": "a", "target_version": "1.0"},
        {"source": "a", "source_version": "1.0", "target": "b", "target_version": "1.0"},
        {"source": "b", "source_version": "1.0", "target": "a", "target_version": "1.0"},
    ]
    status, body = _audit(
        resolved=resolved,
        dependency_graph=graph,
        advisories=[{"id": "CVE-cyc", "package": "b", "affected": "<2"}],
    )
    assert status == 200
    (hit,) = body["findings"]
    assert _names(hit["paths"]) == [["<root>", "a", "b"]]
    for path in hit["paths"]:
        names = [node["name"] for node in path]
        assert len(names) == len(set(names))


def test_unreachable_hit_is_orphaned():
    resolved = {"a": "1.0", "ghost": "1.0"}
    graph = [
        {"source": "<root>", "source_version": "", "target": "a", "target_version": "1.0"},
        {"source": "ghost", "source_version": "1.0", "target": "a", "target_version": "1.0"},
    ]
    status, body = _audit(
        resolved=resolved,
        dependency_graph=graph,
        advisories=[
            {"id": "ADV-a", "package": "a", "affected": ""},
            {"id": "ADV-ghost", "package": "ghost", "affected": "==1.0"},
        ],
    )
    assert status == 200
    assert [entry["advisory"]["id"] for entry in body["findings"]] == ["ADV-a"]
    assert _names(body["findings"][0]["paths"]) == [["<root>", "a"]]
    orphaned = body["orphaned"]
    assert [entry["advisory"]["id"] for entry in orphaned] == ["ADV-ghost"]
    assert orphaned[0]["package"] == "ghost"
    assert orphaned[0]["version"] == "1.0"
    assert "paths" not in orphaned[0]


def test_advisory_for_unresolved_package_does_not_hit():
    status, body = _audit(
        resolved={"a": "1.0"},
        dependency_graph=[
            {"source": "<root>", "source_version": "", "target": "a", "target_version": "1.0"}
        ],
        advisories=[{"id": "ADV-x", "package": "absent", "affected": ""}],
    )
    assert status == 200
    assert body == {"findings": [], "orphaned": []}


def test_package_names_are_canonicalized():
    status, body = _audit(
        resolved={"Some_Pkg.Name": "1.0"},
        dependency_graph=[
            {"source": "<root>", "source_version": "", "target": "some-pkg-name", "target_version": "1.0"}
        ],
        advisories=[{"id": "ADV-1", "package": "some_pkg.name", "affected": ">=1.0"}],
    )
    assert status == 200
    (hit,) = body["findings"]
    assert hit["package"] == "some-pkg-name"
    assert _names(hit["paths"]) == [["<root>", "some-pkg-name"]]


def test_pep440_specifier_semantics():
    graph = [
        {"source": "<root>", "source_version": "", "target": "x", "target_version": "1.0.0"}
    ]
    status, body = _audit(
        resolved={"x": "1.0.0"},
        dependency_graph=graph,
        advisories=[
            {"id": "compatible", "package": "x", "affected": "~=1.0"},
            {"id": "excluded", "package": "x", "affected": "<1,!=1.0"},
            {"id": "prerelease-rule", "package": "x", "affected": ">=1.0rc1"},
        ],
    )
    assert status == 200
    assert sorted(entry["advisory"]["id"] for entry in body["findings"]) == [
        "compatible",
        "prerelease-rule",
    ]
    assert body["orphaned"] == []


def test_empty_advisories():
    status, body = _audit(
        resolved={"a": "1.0"},
        dependency_graph=[
            {"source": "<root>", "source_version": "", "target": "a", "target_version": "1.0"}
        ],
        advisories=[],
    )
    assert status == 200
    assert body == {"findings": [], "orphaned": []}


def test_deterministic_ordering_across_calls():
    advisories = [
        {"id": "Z", "package": "shared", "affected": "<2"},
        {"id": "A", "package": "shared", "affected": "<2"},
        {"id": "M", "package": "app", "affected": ""},
    ]
    payload = {
        "resolved": DIAMOND_RESOLVED,
        "dependency_graph": DIAMOND_GRAPH,
        "advisories": advisories,
    }
    responses = []
    for _ in range(3):
        response = client.post("/audit/vulnerabilities", json=payload)
        responses.append(response.json())
    assert all(r == responses[0] for r in responses)
    assert [entry["advisory"]["id"] for entry in responses[0]["findings"]] == [
        "M",
        "A",
        "Z",
    ]


def test_invalid_resolved_version_returns_400():
    status, body = _audit(
        resolved={"a": "not-a-version"},
        dependency_graph=[
            {"source": "<root>", "source_version": "", "target": "a", "target_version": "not-a-version"}
        ],
        advisories=[],
    )
    assert status == 400
    assert body["error"]["code"] == "invalid_request"
    assert "PEP 440" in body["error"]["message"]


def test_invalid_advisory_specifier_returns_400():
    status, body = _audit(
        resolved={"a": "1.0"},
        dependency_graph=[
            {"source": "<root>", "source_version": "", "target": "a", "target_version": "1.0"}
        ],
        advisories=[{"id": "ADV-1", "package": "a", "affected": ">>>1"}],
    )
    assert status == 400
    assert "specifier" in body["error"]["message"]
    assert "ADV-1" in body["error"]["message"]


def test_dangling_edge_returns_400():
    status, body = _audit(
        resolved={"a": "1.0"},
        dependency_graph=[
            {"source": "<root>", "source_version": "", "target": "ghost", "target_version": "1.0"}
        ],
        advisories=[],
    )
    assert status == 400
    assert "dangling edge" in body["error"]["message"]
    assert "ghost" in body["error"]["message"]


def test_dangling_source_edge_returns_400():
    status, body = _audit(
        resolved={"a": "1.0"},
        dependency_graph=[
            {"source": "phantom", "source_version": "2.0", "target": "a", "target_version": "1.0"}
        ],
        advisories=[],
    )
    assert status == 400
    assert "dangling edge" in body["error"]["message"]


def test_edge_target_version_mismatch_returns_400():
    status, body = _audit(
        resolved={"a": "1.0", "b": "2.0"},
        dependency_graph=[
            {"source": "<root>", "source_version": "", "target": "a", "target_version": "1.0"},
            {"source": "a", "source_version": "1.0", "target": "b", "target_version": "1.0"},
        ],
        advisories=[],
    )
    assert status == 400
    assert "does not match resolved version" in body["error"]["message"]


def test_edge_source_version_mismatch_returns_400():
    status, body = _audit(
        resolved={"a": "1.0", "b": "2.0"},
        dependency_graph=[
            {"source": "<root>", "source_version": "", "target": "a", "target_version": "1.0"},
            {"source": "a", "source_version": "9.9", "target": "b", "target_version": "2.0"},
        ],
        advisories=[],
    )
    assert status == 400
    assert "does not match resolved version" in body["error"]["message"]


def test_root_edge_with_nonempty_version_returns_400():
    status, body = _audit(
        resolved={"a": "1.0"},
        dependency_graph=[
            {"source": "<root>", "source_version": "0.1", "target": "a", "target_version": "1.0"}
        ],
        advisories=[],
    )
    assert status == 400
    assert "<root>" in body["error"]["message"]


def test_edge_targeting_root_returns_400():
    status, body = _audit(
        resolved={"a": "1.0"},
        dependency_graph=[
            {"source": "<root>", "source_version": "", "target": "a", "target_version": "1.0"},
            {"source": "a", "source_version": "1.0", "target": "<root>", "target_version": ""},
        ],
        advisories=[],
    )
    assert status == 400
    assert "only appear as an edge source" in body["error"]["message"]


def test_empty_advisory_id_returns_400():
    status, body = _audit(
        resolved={"a": "1.0"},
        dependency_graph=[
            {"source": "<root>", "source_version": "", "target": "a", "target_version": "1.0"}
        ],
        advisories=[{"id": "", "package": "a", "affected": ""}],
    )
    assert status == 400
    assert "id must be a non-empty string" in body["error"]["message"]


def test_extra_fields_rejected():
    response = client.post(
        "/audit/vulnerabilities",
        json={
            "resolved": {"a": "1.0"},
            "dependency_graph": [],
            "advisories": [],
            "unexpected": 1,
        },
    )
    assert response.status_code == 422


def test_works_with_live_resolve_response():
    resolve_response = client.post(
        "/resolve",
        json={
            "packages": {
                "app": {"1.0": {"dependencies": {"lib": ">=1.0"}}},
                "lib": {"1.0": {}, "2.0": {"dependencies": {"lib": ">=1.0"}}},
            },
            "root": {"app": ""},
        },
    )
    assert resolve_response.status_code == 200
    resolved_body = resolve_response.json()

    status, body = _audit(
        resolved=resolved_body["resolved"],
        dependency_graph=resolved_body["dependency_graph"],
        advisories=[{"id": "GHSA-lib", "package": "lib", "affected": "<3"}],
    )
    assert status == 200
    (hit,) = body["findings"]
    assert hit["version"] == "2.0"
    assert _names(hit["paths"]) == [["<root>", "app", "lib"]]
