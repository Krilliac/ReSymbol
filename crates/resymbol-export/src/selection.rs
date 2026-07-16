use crate::{ExportFunction, ExportProjection};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum SelectedSymbolKind {
    Function,
    Global,
}

impl SelectedSymbolKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Function => "function",
            Self::Global => "global",
        }
    }

    pub(crate) const fn is_function(self) -> bool {
        matches!(self, Self::Function)
    }
}

#[derive(Debug)]
pub(crate) struct SelectedPublicSymbol<'projection> {
    pub(crate) rva: u64,
    pub(crate) kind: SelectedSymbolKind,
    pub(crate) source_name: &'projection str,
    pub(crate) output_name: &'projection str,
}

pub(crate) fn public_symbol_candidate_count(projection: &ExportProjection) -> Option<usize> {
    projection
        .functions
        .iter()
        .filter(|value| value.selected_name.is_some())
        .count()
        .checked_add(
            projection
                .globals
                .iter()
                .filter(|value| value.selected_name.is_some())
                .count(),
        )
}

pub(crate) fn collect_public_symbols<'projection>(
    projection: &'projection ExportProjection,
    values: &mut Vec<SelectedPublicSymbol<'projection>>,
) {
    for function in &projection.functions {
        if let Some(name) = &function.selected_name {
            values.push(SelectedPublicSymbol {
                rva: function.rva,
                kind: SelectedSymbolKind::Function,
                source_name: &name.source.text,
                output_name: &name.output_name,
            });
        }
    }
    for global in &projection.globals {
        if let Some(name) = &global.selected_name {
            values.push(SelectedPublicSymbol {
                rva: global.rva,
                kind: SelectedSymbolKind::Global,
                source_name: &name.source.text,
                output_name: &name.output_name,
            });
        }
    }
    values.sort_by(|left, right| {
        (left.rva, left.kind, left.output_name).cmp(&(right.rva, right.kind, right.output_name))
    });

    // Functions sort first and win only when they have a selected name.
    // Equal-kind duplicate RVAs are forbidden by projection validation.
    values.dedup_by_key(|value| value.rva);
}

#[derive(Debug)]
pub(crate) struct MutationFunctionRecord<'projection> {
    pub(crate) rva: u64,
    pub(crate) size: Option<u64>,
    pub(crate) source_name: Option<&'projection str>,
    pub(crate) output_name: Option<&'projection str>,
}

#[derive(Debug)]
pub(crate) struct MutationGlobalRecord<'projection> {
    pub(crate) rva: u64,
    pub(crate) source_name: &'projection str,
    pub(crate) output_name: &'projection str,
}

#[derive(Debug)]
pub(crate) struct MutationPlan<'projection> {
    pub(crate) functions: Vec<MutationFunctionRecord<'projection>>,
    pub(crate) globals: Vec<MutationGlobalRecord<'projection>>,
    pub(crate) accepted_sizes: Vec<Option<u64>>,
}

pub(crate) fn mutation_plan(projection: &ExportProjection) -> MutationPlan<'_> {
    let accepted_sizes = non_overlapping_function_sizes(&projection.functions);
    let mut functions = Vec::new();
    for (function, size) in projection.functions.iter().zip(&accepted_sizes) {
        if !emits_mutation_function(function, *size) {
            continue;
        }
        functions.push(MutationFunctionRecord {
            rva: function.rva,
            size: *size,
            source_name: function
                .selected_name
                .as_ref()
                .map(|name| name.source.text.as_str()),
            output_name: function
                .selected_name
                .as_ref()
                .map(|name| name.output_name.as_str()),
        });
    }

    let mut globals = Vec::new();
    for global in &projection.globals {
        let Some(name) = &global.selected_name else {
            continue;
        };
        if projection
            .functions
            .binary_search_by_key(&global.rva, |function| function.rva)
            .is_ok_and(|index| {
                emits_mutation_function(&projection.functions[index], accepted_sizes[index])
            })
        {
            continue;
        }
        globals.push(MutationGlobalRecord {
            rva: global.rva,
            source_name: &name.source.text,
            output_name: &name.output_name,
        });
    }

    MutationPlan {
        functions,
        globals,
        accepted_sizes,
    }
}

fn emits_mutation_function(function: &ExportFunction, accepted_size: Option<u64>) -> bool {
    function.selected_name.is_some() || accepted_size.is_some()
}

pub(crate) fn non_overlapping_function_sizes(functions: &[ExportFunction]) -> Vec<Option<u64>> {
    let mut accepted = functions.iter().map(|value| value.size).collect::<Vec<_>>();
    let mut ranges = functions
        .iter()
        .enumerate()
        .filter_map(|(index, value)| {
            let size = value.size?;
            Some((index, value.rva, value.rva.checked_add(size)?))
        })
        .collect::<Vec<_>>();
    ranges.sort_by_key(|value| (value.1, value.2, value.0));

    let mut cluster_start = 0;
    while cluster_start < ranges.len() {
        let mut cluster_end = ranges[cluster_start].2;
        let mut next = cluster_start + 1;
        while next < ranges.len() && ranges[next].1 < cluster_end {
            cluster_end = cluster_end.max(ranges[next].2);
            next += 1;
        }
        if next - cluster_start > 1 {
            for value in &ranges[cluster_start..next] {
                accepted[value.0] = None;
            }
        }
        cluster_start = next;
    }
    accepted
}
