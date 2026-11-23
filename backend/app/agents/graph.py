"""Dependency Graph: nodes/edges from the inventory, plus the shortest path from the
repo root to every component (the "how did this get in here" evidence).

ponytail: graph kept as node/edge lists in the scan record and walked with BFS in
memory. A graph DB (Neo4j) only if cross-repo graph queries become a need.
"""
from collections import Counter, deque


def run(state: dict) -> tuple[dict, dict]:
    root = "repo"
    adj: dict[str, list] = {root: [p["id"] for p in state["projects"]]}
    for e in state["edges"]:
        adj.setdefault(e["source"], []).append(e["target"])

    # BFS: parent pointers give one shortest introduction path per node
    parent, depth = {root: None}, {root: 0}
    queue = deque([root])
    while queue:
        n = queue.popleft()
        for m in adj.get(n, []):
            if m not in parent:
                parent[m], depth[m] = n, depth[n] + 1
                queue.append(m)

    def path(n):
        out = []
        while n is not None:
            out.append(n)
            n = parent[n]
        return out[::-1]

    fan_in = Counter(e["target"] for e in state["edges"])
    fan_out = Counter(e["source"] for e in state["edges"])
    repo_label = state["repo_url"].removeprefix("https://github.com/").removesuffix(".git")
    nodes = [{"id": root, "label": repo_label, "type": "repo", "depth": 0}]
    nodes += [{"id": p["id"], "label": p.get("name") or p["path"], "type": "project", "depth": 1,
               "ecosystem": p["ecosystem"]} for p in state["projects"]]
    for c in state["components"]:
        nodes.append({"id": c["id"], "label": f"{c['name']}@{c['version']}", "type": "component",
                      "depth": depth.get(c["id"]), "direct": c["direct"], "scope": c["scope"],
                      "ecosystem": c["ecosystem"], "dependents": fan_in[c["id"]],
                      "dependencies": fan_out[c["id"]]})
    unreachable = [c["id"] for c in state["components"] if c["id"] not in parent]
    comp_depths = [depth[c["id"]] - 1 for c in state["components"] if c["id"] in depth]  # depth 1 = direct
    edges = [{"source": root, "target": p["id"], "kind": "project"} for p in state["projects"]] + state["edges"]
    top = [{"id": i, "dependents": n} for i, n in fan_in.most_common(10)]
    paths = {c["id"]: path(c["id"]) for c in state["components"] if c["id"] in parent}
    public = {
        "nodes": nodes, "edges": edges, "paths": paths,
        "stats": {"nodes": len(nodes), "edges": len(edges),
                  "max_depth": max(comp_depths, default=0),
                  "depth_histogram": dict(sorted(Counter(comp_depths).items())),
                  "unreachable": len(unreachable)},
        "most_depended_on": top, "unreachable": unreachable[:50],
        "_status": "partial" if unreachable else "done",
        "_summary": f"{len(nodes)} nodes, {len(edges)} edges, max depth {max(comp_depths, default=0)}",
    }
    return {"paths": paths}, public
