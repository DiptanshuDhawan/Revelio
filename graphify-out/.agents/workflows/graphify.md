---
description: Turn any folder of files into a navigable knowledge graph
---

# Workflow: graphify

This project already contains a Graphify knowledge graph.

Primary sources:

- graphify-out/graph.json
- graphify-out/GRAPH_REPORT.md

When graphify-out/graph.json exists:

1. Prefer Graphify MCP tools:
   - query_graph
   - get_node
   - get_neighbors
   - get_community
   - shortest_path
   - graph_stats

2. For architecture, dependency, and codebase questions:
   - Query the existing graph first.
   - Use GRAPH_REPORT.md only for high-level summaries.

3. Do NOT run semantic extraction.

4. Do NOT rebuild the graph.

5. Do NOT invoke the full Graphify pipeline.

Only run Graphify extraction when:
- graph.json is missing
- the user explicitly requests a graph rebuild
- the user explicitly runs /graphify

After code modifications:
- Run graphify update . to refresh the graph incrementally.