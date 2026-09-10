"""The skill trust graph.

A skill is a set of related artifacts and the things they reach, not one file.
Modelling that as a graph makes two questions answerable that a flat file list
cannot answer: *what does this skill ultimately trust*, and *how does an
untrusted thing reach a privileged thing*.

Nodes are typed and carry a trust classification. Edges say why one node depends
on another. The rendering is a tree, because a tree is what a reviewer can read
in ten seconds, but the underlying structure is a graph and paths through it can
be queried.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from skillsniff.analysis.context import AnalysisContext
from skillsniff.analysis.external import TrustLevel
from skillsniff.core.fs import FileKind


class NodeKind(str, Enum):
    SKILL = "skill"
    FILE = "file"
    SCRIPT = "script"
    REFERENCE = "reference"
    ARCHIVE = "archive"
    ARCHIVE_ENTRY = "archive-entry"
    BINARY = "binary"
    DEPENDENCY = "dependency"
    DOMAIN = "domain"
    URL = "url"
    REPOSITORY = "repository"
    TOOL = "tool"
    CAPABILITY = "capability"

    @property
    def glyph(self) -> str:
        return {
            NodeKind.SKILL: "◆",
            NodeKind.FILE: "·",
            NodeKind.SCRIPT: "▸",
            NodeKind.REFERENCE: "·",
            NodeKind.ARCHIVE: "▣",
            NodeKind.ARCHIVE_ENTRY: "·",
            NodeKind.BINARY: "▪",
            NodeKind.DEPENDENCY: "◇",
            NodeKind.DOMAIN: "◈",
            NodeKind.URL: "→",
            NodeKind.REPOSITORY: "⑂",
            NodeKind.TOOL: "⚙",
            NodeKind.CAPABILITY: "▶",
        }[self]


class EdgeKind(str, Enum):
    CONTAINS = "contains"
    REFERENCES = "references"
    DEPENDS_ON = "depends-on"
    FETCHES = "fetches"
    DECLARES = "declares"
    GRANTS = "grants"
    EXERCISES = "exercises"


@dataclass
class Node:
    id: str
    kind: NodeKind
    label: str
    trust: TrustLevel = TrustLevel.UNKNOWN
    detail: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "id": self.id,
            "kind": self.kind.value,
            "label": self.label,
            "trust": self.trust.value,
        }
        if self.detail:
            payload["detail"] = self.detail
        if self.attributes:
            payload["attributes"] = self.attributes
        return payload


@dataclass
class Edge:
    source: str
    target: str
    kind: EdgeKind
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "kind": self.kind.value,
            **({"detail": self.detail} if self.detail else {}),
        }


@dataclass
class TrustGraph:
    root: str
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)

    def add_node(self, node: Node) -> Node:
        existing = self.nodes.get(node.id)
        if existing is not None:
            return existing
        self.nodes[node.id] = node
        return node

    def add_edge(self, source: str, target: str, kind: EdgeKind, detail: str = "") -> None:
        if source in self.nodes and target in self.nodes:
            self.edges.append(Edge(source, target, kind, detail))

    def children(self, node_id: str) -> list[tuple[Node, Edge]]:
        return [
            (self.nodes[e.target], e)
            for e in self.edges
            if e.source == node_id and e.target in self.nodes
        ]

    def by_kind(self, *kinds: NodeKind) -> list[Node]:
        wanted = set(kinds)
        return sorted(
            (n for n in self.nodes.values() if n.kind in wanted), key=lambda n: n.label
        )

    @property
    def untrusted(self) -> list[Node]:
        """Nodes whose content can change after review."""
        return [
            n
            for n in self.nodes.values()
            if n.trust in (TrustLevel.MUTABLE, TrustLevel.SUSPICIOUS, TrustLevel.UNKNOWN)
            and n.kind in (NodeKind.URL, NodeKind.DOMAIN, NodeKind.DEPENDENCY, NodeKind.REPOSITORY)
        ]

    def as_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "nodes": [n.as_dict() for n in self.nodes.values()],
            "edges": [e.as_dict() for e in self.edges],
        }


def build_graph(context: AnalysisContext) -> TrustGraph:
    """Construct the trust graph for one analysed skill."""
    skill = context.skill
    root_id = f"skill:{skill.dir_name}"
    graph = TrustGraph(root=root_id)
    graph.add_node(
        Node(
            id=root_id,
            kind=NodeKind.SKILL,
            label=skill.dir_name,
            trust=TrustLevel.PINNED,
            detail=skill.description[:120],
            attributes={"version": skill.version, "files": len(skill.all_files)},
        )
    )

    # -- files ---------------------------------------------------------------
    for file in context.files:
        scanned = file.scanned
        kind = _node_kind_for(scanned.kind, scanned.relpath, file)
        node_id = f"file:{scanned.display}"
        graph.add_node(
            Node(
                id=node_id,
                kind=kind,
                label=scanned.display,
                trust=TrustLevel.PINNED,
                detail=f"{scanned.size} bytes",
                attributes={"sha256": scanned.sha256[:16], "kind": scanned.kind},
            )
        )
        if scanned.container:
            graph.add_edge(f"file:{scanned.container}", node_id, EdgeKind.CONTAINS)
        else:
            graph.add_edge(root_id, node_id, EdgeKind.CONTAINS)

    # -- declared tools ------------------------------------------------------
    for tool in skill.declared_tools:
        node_id = f"tool:{tool}"
        graph.add_node(Node(id=node_id, kind=NodeKind.TOOL, label=tool, trust=TrustLevel.PINNED))
        graph.add_edge(root_id, node_id, EdgeKind.DECLARES)

    # -- external resources, grouped by domain -------------------------------
    for resource in context.externals:
        if resource.host:
            domain_id = f"domain:{resource.host}"
            graph.add_node(
                Node(
                    id=domain_id,
                    kind=NodeKind.DOMAIN,
                    label=resource.host,
                    trust=resource.trust,
                    detail="; ".join(resource.reasons[:2]),
                )
            )
            source = (
                f"file:{resource.evidence.path}"
                if resource.evidence and f"file:{resource.evidence.path}" in graph.nodes
                else root_id
            )
            graph.add_edge(source, domain_id, EdgeKind.FETCHES, resource.raw[:100])

    # -- dependencies --------------------------------------------------------
    for dependency in context.dependencies:
        node_id = f"dep:{dependency.ecosystem.value}:{dependency.name}"
        graph.add_node(
            Node(
                id=node_id,
                kind=NodeKind.DEPENDENCY,
                label=f"{dependency.name}{(' ' + dependency.version_spec) if dependency.version_spec else ''}",
                trust=dependency.trust,
                detail="; ".join(dependency.reasons[:2]),
                attributes={"ecosystem": dependency.ecosystem.value},
            )
        )
        source = f"file:{dependency.evidence.path}"
        graph.add_edge(
            source if source in graph.nodes else root_id, node_id, EdgeKind.DEPENDS_ON
        )

    # -- capabilities --------------------------------------------------------
    for capability in sorted(context.capabilities.all, key=lambda c: c.value):
        node_id = f"cap:{capability.value}"
        undeclared = capability in context.capabilities.undeclared
        graph.add_node(
            Node(
                id=node_id,
                kind=NodeKind.CAPABILITY,
                label=capability.value,
                trust=TrustLevel.SUSPICIOUS if undeclared and capability.is_privileged else TrustLevel.PINNED,
                detail=capability.label + (" (undeclared)" if undeclared else ""),
                attributes={
                    "privileged": capability.is_privileged,
                    "undeclared": undeclared,
                    "sources": sorted(s.value for s in context.capabilities.sources_for(capability)),
                },
            )
        )
        for observation in context.capabilities.by_capability(capability):
            source = f"file:{observation.evidence.path}"
            graph.add_edge(
                source if source in graph.nodes else root_id,
                node_id,
                EdgeKind.EXERCISES,
                observation.detail[:80],
            )

    return graph


def _node_kind_for(file_kind: str, relpath: str, file: Any) -> NodeKind:
    if file_kind == FileKind.ARCHIVE:
        return NodeKind.ARCHIVE
    if file_kind == FileKind.EXECUTABLE:
        return NodeKind.BINARY
    if getattr(file.scanned, "container", ""):
        return NodeKind.ARCHIVE_ENTRY
    if file.python is not None or file.shell is not None or relpath.endswith((".py", ".sh", ".js", ".ts")):
        return NodeKind.SCRIPT
    if relpath.startswith(("references/", "docs/", "reference/")):
        return NodeKind.REFERENCE
    return NodeKind.FILE


def render_tree(graph: TrustGraph, max_children: int = 12) -> Iterator[str]:
    """Render the graph as an indented tree, deduplicating shared targets."""
    yield f"{NodeKind.SKILL.glyph} {graph.nodes[graph.root].label}"

    groups: list[tuple[str, list[Node]]] = [
        ("files", [n for n in graph.by_kind(NodeKind.FILE, NodeKind.SCRIPT, NodeKind.REFERENCE) if not _inside_archive(graph, n.id)]),
        ("archives", graph.by_kind(NodeKind.ARCHIVE)),
        ("binaries", graph.by_kind(NodeKind.BINARY)),
        ("declared tools", graph.by_kind(NodeKind.TOOL)),
        ("dependencies", graph.by_kind(NodeKind.DEPENDENCY)),
        ("external domains", graph.by_kind(NodeKind.DOMAIN)),
        ("capabilities", graph.by_kind(NodeKind.CAPABILITY)),
    ]

    populated = [(label, nodes) for label, nodes in groups if nodes]
    for group_index, (label, nodes) in enumerate(populated):
        last_group = group_index == len(populated) - 1
        branch = "└──" if last_group else "├──"
        pad = "    " if last_group else "│   "
        yield f"{branch} {label} ({len(nodes)})"

        shown = nodes[:max_children]
        for index, node in enumerate(shown):
            last = index == len(shown) - 1 and len(nodes) <= max_children
            sub = "└──" if last else "├──"
            trust = "" if node.trust is TrustLevel.PINNED else f"  [{node.trust.value}]"
            detail = f"  — {node.detail}" if node.detail and node.kind is not NodeKind.FILE else ""
            yield f"{pad}{sub} {node.kind.glyph} {node.label}{trust}{detail}"

            if node.kind is NodeKind.ARCHIVE:
                entries = [n for n, _ in graph.children(node.id)]
                inner_pad = f"{pad}    " if last else f"{pad}│   "
                for entry_index, entry in enumerate(entries[:6]):
                    inner_last = entry_index == min(len(entries), 6) - 1
                    yield f"{inner_pad}{'└──' if inner_last else '├──'} {entry.kind.glyph} {entry.label.split('!')[-1]}"
                if len(entries) > 6:
                    yield f"{inner_pad}└── … {len(entries) - 6} more"

        if len(nodes) > max_children:
            yield f"{pad}└── … {len(nodes) - max_children} more"


def _inside_archive(graph: TrustGraph, node_id: str) -> bool:
    return any(
        e.target == node_id and e.kind is EdgeKind.CONTAINS and graph.nodes[e.source].kind is NodeKind.ARCHIVE
        for e in graph.edges
    )
