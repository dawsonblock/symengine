"""Opt-in, non-neural learning primitives. Candidates never self-qualify."""
from .strategies import EpisodeEvidence, StrategyCandidate, induce_strategies
from .symbolic import StructuralChange, induce_structural_change
from .optimization import CandidateTrial, select_improvement

__all__ = ["EpisodeEvidence", "StrategyCandidate", "induce_strategies", "StructuralChange", "induce_structural_change", "CandidateTrial", "select_improvement"]
from .records import strategy_to_record, structure_to_record
__all__ += ["strategy_to_record", "structure_to_record"]
