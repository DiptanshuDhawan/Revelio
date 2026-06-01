---
trigger: always_on
description: Consult the graphify knowledge graph at graphify-out/ for codebase and architecture questions.
---

## graphify

This project has a Graphify knowledge graph at graphify-out/.

When Graphify MCP is available:

- Prefer MCP graph tools over repository scanning.
- Prefer query_graph over graph extraction.
- Prefer get_node, get_neighbors, get_community, shortest_path, and graph_stats for architecture and codebase questions.
- Use graph relationships to locate relevant code before reading source files.
- Do not run semantic extraction if graphify-out/graph.json exists.
- Do not rebuild the graph unless explicitly requested by the user.
- Use GRAPH_REPORT.md only when graph queries do not provide sufficient context.
- Avoid repository-wide scans whenever possible.

For architecture, dependency, design, and codebase questions:

1. Query the graph first.
2. Analyze returned nodes and relationships.
3. Use shortest-path and neighborhood exploration when tracing flows.
4. Read source files only when implementation details are required.
5. Limit file reads to the files identified by graph traversal.

Rules:

- For codebase or architecture questions, when graphify-out/graph.json exists, first use Graphify MCP tools:
  - query_graph for architecture and semantic questions.
  - get_node for focused concepts.
  - get_neighbors for related modules.
  - shortest_path for dependency tracing and flow analysis.
  - graph_stats for repository structure insights.
  - get_community for subsystem discovery.

- If MCP tools are unavailable, run:
  - graphify query "<question>" (CLI)

- If graphify-out/wiki/index.md exists, navigate it instead of reading raw files.

- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when graph queries do not surface enough context.

- After modifying code files in this session, run:
  - graphify update .
  to keep the graph current (AST-only, no API cost).

- Run a full Graphify extraction only when:
  - graph.json is missing,
  - the graph is clearly outdated,
  - or the user explicitly requests a graph rebuild.

Never rebuild the graph for ordinary architecture questions when a valid graph.json already exists.