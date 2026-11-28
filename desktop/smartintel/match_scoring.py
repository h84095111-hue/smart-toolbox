"""Transparent triage scoring; this is not a calibrated statistical probability."""
from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Iterable

@dataclass
class RiskAssessment:
    score: int
    risk_band: str
    label: str
    factors: list[dict]
    calibration: str = "uncalibrated_heuristic"
    disclaimer: str = "Heuristic triage index, not a statistically calibrated false-positive probability."
    def to_dict(self): return asdict(self)

def assess_false_positive_risk(*, exact_email: bool=False, exact_phone: bool=False,
    cross_linked_profile: bool=False, independent_sources: int=0,
    contradictions: int=0, popular_handle: bool=False,
    display_name_only: bool=False, stale_sources: int=0) -> RiskAssessment:
    """Return a 0-100 risk index; higher means more caution / false-positive risk."""
    score=55
    factors=[]
    def apply(name,delta,reason):
        nonlocal score
        score+=delta
        factors.append({"factor":name,"impact":delta,"reason":reason})
    if exact_email: apply("exact_email",-28,"Exact email string is a stronger link, but mailbox ownership is not verified.")
    if exact_phone: apply("exact_phone",-18,"Exact normalized phone string is a stronger link, but subscriber ownership is not verified.")
    if cross_linked_profile: apply("cross_linked_profile",-22,"A profile explicitly links to another profile or identifier.")
    if independent_sources: apply("independent_sources",-min(18,6*min(independent_sources,3)),f"{independent_sources} independent source(s) corroborate the lead.")
    if contradictions: apply("contradictions",min(35,15*contradictions),"Conflicting attributes increase the chance of a false match.")
    if popular_handle: apply("popular_handle",15,"Common or widely reused handles are weak identifiers.")
    if display_name_only: apply("display_name_only",22,"Display-name similarity alone is not identity evidence.")
    if stale_sources: apply("stale_sources",min(15,5*stale_sources),"Older evidence may no longer describe the same account or person.")
    score=max(5,min(100,score))
    band="low" if score<30 else "moderate" if score<60 else "high"
    return RiskAssessment(score,band,"Higher score means higher false-positive concern",factors)

def calibration_status(labeled_examples: int) -> str:
    if labeled_examples < 100: return "uncalibrated: at least 100 labeled examples required before calibration is considered"
    return "calibration_candidate: validate with held-out data and report calibration metrics before showing probability"
