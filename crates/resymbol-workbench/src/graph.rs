//! Deterministic, evidence-preserving indexes for the reconstruction graph.
//!
//! This module deliberately owns no rendering state.  It turns the canonical
//! projection into stable nodes and exact, attributed edges, then exposes a
//! bounded breadth-first view that a canvas can lay out without silently
//! changing the underlying relationships.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use resymbol_analysis::{BinaryAnalysis, ImportTarget};
use resymbol_export::{ExportAttribution, ExportControlFlowTarget, ExportProducer};

use crate::model::{FunctionStatus, LoadedProject};

pub(crate) const GRAPH_MAX_NODES: usize = 36;
pub(crate) const GRAPH_MAX_EDGES: usize = 96;
pub(crate) const GRAPH_MAX_DEPTH: usize = 4;

/// Stable identity for graph nodes.  The variant keeps an IAT slot distinct
/// from a function that happens to use the same numeric RVA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum GraphNodeId {
    Function(u64),
    ImportIat(u64),
}

impl GraphNodeId {
    #[must_use]
    pub(crate) const fn rva(self) -> u64 {
        match self {
            Self::Function(rva) | Self::ImportIat(rva) => rva,
        }
    }
}

/// Whether a terminal IAT node came from the normal or delay-load inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum GraphImportKind {
    Normal,
    Delay,
    /// Defensive fallback for a future projection whose import target cannot
    /// be resolved through the format-specific inventory.
    Unresolved,
}

/// Semantic kind and format-owned identity for a graph node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GraphNodeKind {
    Function,
    ImportIat {
        library: String,
        symbol: String,
        import_kind: GraphImportKind,
    },
}

/// One canonical graph node.  Projected functions retain their stable row
/// index; terminal imports and defensive relationship-only nodes do not have
/// one and therefore cannot masquerade as selectable function rows.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct GraphNode {
    pub(crate) id: GraphNodeId,
    pub(crate) rva: u64,
    pub(crate) projection_index: Option<usize>,
    pub(crate) name: String,
    pub(crate) status: Option<FunctionStatus>,
    pub(crate) confidence: Option<f64>,
    pub(crate) kind: GraphNodeKind,
}

/// The visual category of a retained relationship.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum GraphEdgeKind {
    DirectCall,
    Thunk,
    FunctionPointer,
}

/// Whether an edge was projected from a call instruction or a thunk entry.
/// This remains independent from `GraphEdgeKind`, so function-pointer calls
/// and function-pointer thunks retain both facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum GraphEdgeOrigin {
    DirectCall,
    Thunk,
}

/// Exact attribution copied from the selected projection relationship.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct GraphAttribution {
    pub(crate) confidence: f64,
    pub(crate) producer: ExportProducer,
    pub(crate) method: String,
    pub(crate) run_id: Option<String>,
}

impl From<&ExportAttribution> for GraphAttribution {
    fn from(value: &ExportAttribution) -> Self {
        Self {
            confidence: value.confidence,
            producer: value.provenance.producer.clone(),
            method: value.provenance.method.clone(),
            run_id: value.provenance.run_id.clone(),
        }
    }
}

/// One exact relationship.  Repeated targets at different call sites remain
/// separate edges; no canvas-oriented aggregation is performed here.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct GraphEdge {
    pub(crate) source: GraphNodeId,
    pub(crate) target: GraphNodeId,
    pub(crate) kind: GraphEdgeKind,
    pub(crate) origin: GraphEdgeOrigin,
    pub(crate) call_site_rva: Option<u64>,
    pub(crate) pointer_slot_rva: Option<u64>,
    pub(crate) attribution: GraphAttribution,
}

/// Why the default graph root was selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GraphRootKind {
    EntryPoint,
    LowestProjectedFunction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GraphRoot {
    pub(crate) rva: u64,
    pub(crate) kind: GraphRootKind,
}

/// One node admitted to a bounded view and its shortest outgoing-edge depth
/// from the requested function root.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ReconstructionGraphViewNode {
    pub(crate) depth: usize,
    pub(crate) node: GraphNode,
}

/// A deterministic canvas-sized slice of the stored graph.
///
/// Omission counts describe the immediate frontier encountered while walking
/// admitted nodes.  Descendants of an omitted node are intentionally not
/// traversed, keeping both work and memory bounded by the visible slice.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ReconstructionGraphView {
    pub(crate) root: Option<GraphNodeId>,
    pub(crate) nodes: Vec<ReconstructionGraphViewNode>,
    pub(crate) edges: Vec<GraphEdge>,
    pub(crate) omitted_node_count: usize,
    pub(crate) omitted_edge_count: usize,
}

impl ReconstructionGraphView {
    #[must_use]
    pub(crate) const fn is_truncated(&self) -> bool {
        self.omitted_node_count != 0 || self.omitted_edge_count != 0
    }
}

/// Canonical graph index for one loaded project.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ReconstructionGraph {
    nodes: BTreeMap<GraphNodeId, GraphNode>,
    edges: Vec<GraphEdge>,
    adjacency: BTreeMap<GraphNodeId, Vec<usize>>,
    default_root: Option<GraphRoot>,
}

impl ReconstructionGraph {
    /// Build a deterministic index without reconciling or inventing evidence.
    #[must_use]
    pub(crate) fn from_project(project: &LoadedProject) -> Self {
        let mut nodes = project
            .functions
            .iter()
            .map(|row| {
                let id = GraphNodeId::Function(row.rva);
                (
                    id,
                    GraphNode {
                        id,
                        rva: row.rva,
                        projection_index: Some(row.projection_index),
                        name: row.display_name.clone(),
                        status: Some(row.status),
                        confidence: row.confidence,
                        kind: GraphNodeKind::Function,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        let import_lookup = pe_import_lookup(project);
        let mut edges = Vec::with_capacity(
            project.projection.direct_calls.len() + project.projection.thunks.len(),
        );

        for call in &project.projection.direct_calls {
            let source = GraphNodeId::Function(call.caller_rva);
            ensure_function_node(&mut nodes, call.caller_rva);
            let (target, kind, pointer_slot_rva) = graph_target(
                &mut nodes,
                &import_lookup,
                &call.target,
                GraphEdgeKind::DirectCall,
            );
            edges.push(GraphEdge {
                source,
                target,
                kind,
                origin: GraphEdgeOrigin::DirectCall,
                call_site_rva: Some(call.call_site_rva),
                pointer_slot_rva,
                attribution: GraphAttribution::from(&call.attribution),
            });
        }

        for thunk in &project.projection.thunks {
            let source = GraphNodeId::Function(thunk.rva);
            ensure_function_node(&mut nodes, thunk.rva);
            let (target, kind, pointer_slot_rva) = graph_target(
                &mut nodes,
                &import_lookup,
                &thunk.target,
                GraphEdgeKind::Thunk,
            );
            edges.push(GraphEdge {
                source,
                target,
                kind,
                origin: GraphEdgeOrigin::Thunk,
                call_site_rva: None,
                pointer_slot_rva,
                attribution: GraphAttribution::from(&thunk.attribution),
            });
        }

        sort_edges(&mut edges);
        let mut adjacency = nodes
            .keys()
            .copied()
            .map(|id| (id, Vec::new()))
            .collect::<BTreeMap<_, _>>();
        for (index, edge) in edges.iter().enumerate() {
            adjacency.entry(edge.source).or_default().push(index);
        }

        let default_root = default_root(project, &nodes);
        Self {
            nodes,
            edges,
            adjacency,
            default_root,
        }
    }

    #[must_use]
    pub(crate) const fn default_root(&self) -> Option<GraphRoot> {
        self.default_root
    }

    /// Return a deterministic bounded outgoing graph rooted at a projected
    /// function.  An unknown or import RVA produces an empty view.
    #[must_use]
    pub(crate) fn view(&self, root_rva: u64) -> ReconstructionGraphView {
        self.view_with_limits(root_rva, GRAPH_MAX_NODES, GRAPH_MAX_EDGES, GRAPH_MAX_DEPTH)
    }

    fn view_with_limits(
        &self,
        root_rva: u64,
        max_nodes: usize,
        max_edges: usize,
        max_depth: usize,
    ) -> ReconstructionGraphView {
        let root = GraphNodeId::Function(root_rva);
        if max_nodes == 0 || !self.nodes.contains_key(&root) {
            return ReconstructionGraphView {
                root: None,
                nodes: Vec::new(),
                edges: Vec::new(),
                omitted_node_count: 0,
                omitted_edge_count: 0,
            };
        }

        let mut depths = BTreeMap::from([(root, 0_usize)]);
        let mut queue = VecDeque::from([root]);
        let mut included_edge_indices = BTreeSet::new();
        let mut omitted_nodes = BTreeSet::new();
        let mut omitted_edge_count = 0_usize;

        while let Some(source) = queue.pop_front() {
            let depth = depths[&source];
            let Some(outgoing) = self.adjacency.get(&source) else {
                continue;
            };

            for &edge_index in outgoing {
                let edge = &self.edges[edge_index];
                let target_is_admitted = depths.contains_key(&edge.target);
                if target_is_admitted {
                    // Cycles and self edges remain visible, but admitted nodes
                    // are never enqueued a second time.
                    if included_edge_indices.len() < max_edges {
                        included_edge_indices.insert(edge_index);
                    } else {
                        omitted_edge_count = omitted_edge_count.saturating_add(1);
                    }
                    continue;
                }

                let target_depth = depth.saturating_add(1);
                if target_depth > max_depth
                    || depths.len() >= max_nodes
                    || included_edge_indices.len() >= max_edges
                {
                    omitted_nodes.insert(edge.target);
                    omitted_edge_count = omitted_edge_count.saturating_add(1);
                    continue;
                }

                depths.insert(edge.target, target_depth);
                omitted_nodes.remove(&edge.target);
                included_edge_indices.insert(edge_index);
                queue.push_back(edge.target);
            }
        }

        let mut nodes = depths
            .into_iter()
            .filter_map(|(id, depth)| {
                self.nodes
                    .get(&id)
                    .cloned()
                    .map(|node| ReconstructionGraphViewNode { depth, node })
            })
            .collect::<Vec<_>>();
        nodes.sort_by_key(|view_node| (view_node.depth, view_node.node.id));
        let edges = included_edge_indices
            .into_iter()
            .map(|index| self.edges[index].clone())
            .collect();

        ReconstructionGraphView {
            root: Some(root),
            nodes,
            edges,
            omitted_node_count: omitted_nodes.len(),
            omitted_edge_count,
        }
    }
}

#[derive(Debug, Clone)]
struct ResolvedImport {
    library: String,
    symbol: String,
    import_kind: GraphImportKind,
}

fn pe_import_lookup(project: &LoadedProject) -> BTreeMap<u64, ResolvedImport> {
    let BinaryAnalysis::Pe(pe) = project.session().base_analysis() else {
        return BTreeMap::new();
    };
    let mut imports = BTreeMap::new();
    for library in &pe.imports {
        for entry in &library.entries {
            imports.insert(
                u64::from(entry.iat_rva),
                ResolvedImport {
                    library: library.name.clone(),
                    symbol: import_symbol(&entry.target),
                    import_kind: GraphImportKind::Normal,
                },
            );
        }
    }
    for library in &pe.delay_imports {
        for entry in &library.entries {
            imports.insert(
                u64::from(entry.iat_rva),
                ResolvedImport {
                    library: library.name.clone(),
                    symbol: import_symbol(&entry.target),
                    import_kind: GraphImportKind::Delay,
                },
            );
        }
    }
    imports
}

fn import_symbol(target: &ImportTarget) -> String {
    match target {
        ImportTarget::Name { name, .. } => name.clone(),
        ImportTarget::Ordinal { ordinal } => format!("#{ordinal}"),
    }
}

fn ensure_function_node(nodes: &mut BTreeMap<GraphNodeId, GraphNode>, rva: u64) {
    let id = GraphNodeId::Function(rva);
    nodes.entry(id).or_insert_with(|| GraphNode {
        id,
        rva,
        projection_index: None,
        name: format!("sub_{rva:08x}"),
        status: None,
        confidence: None,
        kind: GraphNodeKind::Function,
    });
}

fn graph_target(
    nodes: &mut BTreeMap<GraphNodeId, GraphNode>,
    import_lookup: &BTreeMap<u64, ResolvedImport>,
    target: &ExportControlFlowTarget,
    ordinary_kind: GraphEdgeKind,
) -> (GraphNodeId, GraphEdgeKind, Option<u64>) {
    match target {
        ExportControlFlowTarget::Function { rva } => {
            ensure_function_node(nodes, *rva);
            (GraphNodeId::Function(*rva), ordinary_kind, None)
        }
        ExportControlFlowTarget::ImportIat { iat_rva } => {
            let id = GraphNodeId::ImportIat(*iat_rva);
            nodes.entry(id).or_insert_with(|| {
                let resolved = import_lookup.get(iat_rva);
                let (library, symbol, import_kind) = resolved.map_or_else(
                    || {
                        (
                            "<unresolved>".to_owned(),
                            format!("IAT 0x{iat_rva:x}"),
                            GraphImportKind::Unresolved,
                        )
                    },
                    |resolved| {
                        (
                            resolved.library.clone(),
                            resolved.symbol.clone(),
                            resolved.import_kind,
                        )
                    },
                );
                GraphNode {
                    id,
                    rva: *iat_rva,
                    projection_index: None,
                    name: format!("{library}!{symbol}"),
                    status: None,
                    confidence: None,
                    kind: GraphNodeKind::ImportIat {
                        library,
                        symbol,
                        import_kind,
                    },
                }
            });
            (id, ordinary_kind, None)
        }
        ExportControlFlowTarget::FunctionPointer { slot_rva, rva } => {
            ensure_function_node(nodes, *rva);
            (
                GraphNodeId::Function(*rva),
                GraphEdgeKind::FunctionPointer,
                Some(*slot_rva),
            )
        }
        _ => unreachable!("validated projection emitted an unknown control-flow target"),
    }
}

fn default_root(
    project: &LoadedProject,
    nodes: &BTreeMap<GraphNodeId, GraphNode>,
) -> Option<GraphRoot> {
    let entry_point_rva = match project.session().base_analysis() {
        BinaryAnalysis::Pe(pe) => u64::from(pe.entry_point_rva),
        _ => 0,
    };
    default_root_for_entry(entry_point_rva, nodes)
}

fn default_root_for_entry(
    entry_point_rva: u64,
    nodes: &BTreeMap<GraphNodeId, GraphNode>,
) -> Option<GraphRoot> {
    if entry_point_rva != 0
        && nodes
            .get(&GraphNodeId::Function(entry_point_rva))
            .is_some_and(|node| node.projection_index.is_some())
    {
        return Some(GraphRoot {
            rva: entry_point_rva,
            kind: GraphRootKind::EntryPoint,
        });
    }

    nodes
        .values()
        .filter(|node| {
            matches!(node.id, GraphNodeId::Function(_)) && node.projection_index.is_some()
        })
        .map(|node| node.rva)
        .min()
        .map(|rva| GraphRoot {
            rva,
            kind: GraphRootKind::LowestProjectedFunction,
        })
}

fn sort_edges(edges: &mut [GraphEdge]) {
    edges.sort_by(|left, right| {
        edge_site(left)
            .cmp(&edge_site(right))
            .then_with(|| left.source.cmp(&right.source))
            .then_with(|| left.origin.cmp(&right.origin))
            .then_with(|| left.kind.cmp(&right.kind))
            .then_with(|| left.target.cmp(&right.target))
            .then_with(|| left.pointer_slot_rva.cmp(&right.pointer_slot_rva))
            .then_with(|| attribution_order(&left.attribution, &right.attribution))
    });
}

fn edge_site(edge: &GraphEdge) -> u64 {
    edge.call_site_rva
        .or(edge.pointer_slot_rva)
        .unwrap_or_else(|| edge.source.rva())
}

fn attribution_order(left: &GraphAttribution, right: &GraphAttribution) -> std::cmp::Ordering {
    left.producer
        .cmp(&right.producer)
        .then_with(|| left.method.cmp(&right.method))
        .then_with(|| left.run_id.cmp(&right.run_id))
        .then_with(|| left.confidence.total_cmp(&right.confidence))
}

#[cfg(test)]
mod tests {
    use super::*;
    use resymbol_app::AppServices;
    use std::io::Write as _;
    use tempfile::NamedTempFile;

    const OPTIMIZED_FIXTURE: &[u8] =
        include_bytes!("../../../fixtures/pe-x64-msvc/artifacts/milestone2-stripped.exe");

    fn optimized_project() -> LoadedProject {
        let mut source = NamedTempFile::new().expect("temporary optimized PE");
        source
            .write_all(OPTIMIZED_FIXTURE)
            .expect("write optimized fixture");
        let snapshot = AppServices::default()
            .analyze_binary(source.path())
            .expect("service-backed optimized fixture analysis");
        LoadedProject::from_snapshot(snapshot).expect("optimized fixture should load")
    }

    #[test]
    fn optimized_fixture_keeps_entry_calls_imports_and_attribution_deterministic() {
        let project = optimized_project();
        let graph = ReconstructionGraph::from_project(&project);

        assert_eq!(
            graph.default_root(),
            Some(GraphRoot {
                rva: 0x1060,
                kind: GraphRootKind::EntryPoint,
            })
        );

        let caller = GraphNodeId::Function(0x1030);
        let child_names = graph.adjacency[&caller]
            .iter()
            .map(|&index| graph.nodes[&graph.edges[index].target].name.as_str())
            .collect::<BTreeSet<_>>();
        assert!(child_names.contains("fixture_leaf"));
        assert!(child_names.contains("fixture_string_score"));
        let caller_view = graph.view(0x1030);
        let caller_view_rvas = caller_view
            .nodes
            .iter()
            .map(|node| node.node.rva)
            .collect::<BTreeSet<_>>();
        assert!(caller_view_rvas.contains(&0x10d0));
        assert!(caller_view_rvas.contains(&0x10e0));

        assert_eq!(
            default_root_for_entry(0, &graph.nodes),
            Some(GraphRoot {
                rva: 0x1000,
                kind: GraphRootKind::LowestProjectedFunction,
            })
        );

        let get_tick_count = graph.nodes.values().find(|node| {
            matches!(node.kind, GraphNodeKind::ImportIat { .. })
                && node.name.ends_with("!GetTickCount")
        });
        assert!(
            get_tick_count.is_some(),
            "referenced imports become terminal nodes"
        );

        assert!(graph.edges.iter().any(|edge| {
            edge.kind == GraphEdgeKind::DirectCall
                && edge.origin == GraphEdgeOrigin::DirectCall
                && edge.call_site_rva.is_some()
                && edge.attribution.confidence > 0.0
                && !edge.attribution.method.is_empty()
        }));
        assert!(graph.edges.iter().any(|edge| {
            edge.kind == GraphEdgeKind::Thunk
                && edge.origin == GraphEdgeOrigin::Thunk
                && edge.call_site_rva.is_none()
        }));
        for pointer_edge in graph
            .edges
            .iter()
            .filter(|edge| edge.kind == GraphEdgeKind::FunctionPointer)
        {
            assert!(pointer_edge.pointer_slot_rva.is_some());
        }

        let first = graph.view(0x1060);
        let second = ReconstructionGraph::from_project(&project).view(0x1060);
        assert_eq!(first, second);
        assert!(first.nodes.len() <= GRAPH_MAX_NODES);
        assert!(first.edges.len() <= GRAPH_MAX_EDGES);
        assert!(first.nodes.iter().all(|node| node.depth <= GRAPH_MAX_DEPTH));
    }

    #[test]
    fn bounded_view_keeps_cycles_and_reports_the_omitted_frontier() {
        let attribution = GraphAttribution {
            confidence: 1.0,
            producer: ExportProducer::Core {
                component: "test".to_owned(),
                version: "1.0.0".to_owned(),
            },
            method: "synthetic-edge".to_owned(),
            run_id: Some("graph-test".to_owned()),
        };
        let nodes = (0_u64..=8)
            .map(|rva| {
                let id = GraphNodeId::Function(rva);
                (
                    id,
                    GraphNode {
                        id,
                        rva,
                        projection_index: Some(rva as usize),
                        name: format!("f{rva}"),
                        status: Some(FunctionStatus::EvidenceBacked),
                        confidence: Some(1.0),
                        kind: GraphNodeKind::Function,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        let mut edges = (1_u64..=8)
            .map(|target| GraphEdge {
                source: GraphNodeId::Function(0),
                target: GraphNodeId::Function(target),
                kind: GraphEdgeKind::DirectCall,
                origin: GraphEdgeOrigin::DirectCall,
                call_site_rva: Some(0x1000 + target),
                pointer_slot_rva: None,
                attribution: attribution.clone(),
            })
            .collect::<Vec<_>>();
        edges.push(GraphEdge {
            source: GraphNodeId::Function(0),
            target: GraphNodeId::Function(0),
            kind: GraphEdgeKind::DirectCall,
            origin: GraphEdgeOrigin::DirectCall,
            call_site_rva: Some(0x2000),
            pointer_slot_rva: None,
            attribution,
        });
        sort_edges(&mut edges);
        let mut adjacency = nodes
            .keys()
            .copied()
            .map(|id| (id, Vec::new()))
            .collect::<BTreeMap<_, _>>();
        for (index, edge) in edges.iter().enumerate() {
            adjacency.entry(edge.source).or_default().push(index);
        }
        let graph = ReconstructionGraph {
            nodes,
            edges,
            adjacency,
            default_root: Some(GraphRoot {
                rva: 0,
                kind: GraphRootKind::LowestProjectedFunction,
            }),
        };

        let view = graph.view_with_limits(0, 4, 4, 1);
        assert_eq!(view.nodes.len(), 4);
        assert_eq!(view.edges.len(), 4);
        assert_eq!(view.omitted_node_count, 5);
        assert_eq!(view.omitted_edge_count, 5);
        assert!(view.edges.iter().any(|edge| edge.source == edge.target));
        assert!(view.is_truncated());
    }

    #[test]
    fn repeated_calls_and_thunks_between_the_same_nodes_remain_distinct() {
        let attribution = GraphAttribution {
            confidence: 0.95,
            producer: ExportProducer::Core {
                component: "test".to_owned(),
                version: "1.0.0".to_owned(),
            },
            method: "synthetic-edge".to_owned(),
            run_id: None,
        };
        let nodes = [0_u64, 1]
            .into_iter()
            .map(|rva| {
                let id = GraphNodeId::Function(rva);
                (
                    id,
                    GraphNode {
                        id,
                        rva,
                        projection_index: Some(rva as usize),
                        name: format!("f{rva}"),
                        status: Some(FunctionStatus::EvidenceBacked),
                        confidence: Some(0.95),
                        kind: GraphNodeKind::Function,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        let source = GraphNodeId::Function(0);
        let target = GraphNodeId::Function(1);
        let mut edges = vec![
            GraphEdge {
                source,
                target,
                kind: GraphEdgeKind::DirectCall,
                origin: GraphEdgeOrigin::DirectCall,
                call_site_rva: Some(0x1000),
                pointer_slot_rva: None,
                attribution: attribution.clone(),
            },
            GraphEdge {
                source,
                target,
                kind: GraphEdgeKind::DirectCall,
                origin: GraphEdgeOrigin::DirectCall,
                call_site_rva: Some(0x1005),
                pointer_slot_rva: None,
                attribution: attribution.clone(),
            },
            GraphEdge {
                source,
                target,
                kind: GraphEdgeKind::Thunk,
                origin: GraphEdgeOrigin::Thunk,
                call_site_rva: None,
                pointer_slot_rva: None,
                attribution,
            },
        ];
        sort_edges(&mut edges);
        let adjacency = BTreeMap::from([(source, vec![0, 1, 2]), (target, Vec::new())]);
        let graph = ReconstructionGraph {
            nodes,
            edges,
            adjacency,
            default_root: Some(GraphRoot {
                rva: 0,
                kind: GraphRootKind::LowestProjectedFunction,
            }),
        };

        let view = graph.view_with_limits(0, 4, 8, 2);
        assert_eq!(view.edges.len(), 3);
        assert_eq!(
            view.edges
                .iter()
                .filter_map(|edge| edge.call_site_rva)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([0x1000, 0x1005])
        );
        assert!(
            view.edges
                .iter()
                .any(|edge| edge.origin == GraphEdgeOrigin::Thunk)
        );
    }
}
