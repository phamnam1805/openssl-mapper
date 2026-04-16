#!/usr/bin/env python3
"""
Compare two .automaton files for isomorphism using NetworkX.

Format per file:
  Line 1: space-separated input symbols (alphabet)
  Lines 2+: from_state, to_state, input, output
"""

import sys
import networkx as nx
from networkx.algorithms import isomorphism


def parse_automaton(path):
    """Parse .automaton file and return a NetworkX MultiDiGraph.

    Each edge has attributes:
      - input:  the input symbol
      - output: the output symbol
      - label:  combined "input/output" used for edge matching
    """
    with open(path, encoding="utf-8") as f:
        lines = [l.strip() for l in f if l.strip()]

    G = nx.MultiDiGraph()

    for line in lines[1:]:
        parts = line.split(",", 3)
        if len(parts) < 4:
            continue
        from_state = parts[0].strip()
        to_state   = parts[1].strip()
        inp        = parts[2].strip()
        output     = parts[3].strip()
        G.add_edge(from_state, to_state, input=inp, output=output, label=f"{inp}/{output}")

    return G


def check_isomorphic(automaton_file_1, automaton_file_2):
    print(f"\nComparing:\n  {automaton_file_1}\n  {automaton_file_2}")

    G1 = parse_automaton(automaton_file_1)
    G2 = parse_automaton(automaton_file_2)

    print(f"  G1: {G1.number_of_nodes()} states, {G1.number_of_edges()} transitions")
    print(f"  G2: {G2.number_of_nodes()} states, {G2.number_of_edges()} transitions")

    em = isomorphism.categorical_multiedge_match('label', '')
    GM = isomorphism.MultiDiGraphMatcher(G1, G2, edge_match=em)

    if GM.is_isomorphic():
        print(f"  Isomorphic: True")
        print(f"  Mapping: {GM.mapping}")
    else:
        print(f"  Isomorphic: False")


check_isomorphic(
    "logs/oob-bdist3/final.automaton",
    "logs/original-bdist3/final.automaton",
)

# check_isomorphic(
#     "logs/original-final.automaton",
#     "logs/oob-final.automaton",
# )
