"""Transparent triage scoring; not a calibrated statistical probability."""
from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Any
import re
from urllib.parse import urlparse

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
    """Return a 0-100 caution index; higher means greater false-match concern."""
    score=55
    factors=[]
    def apply(name,delta,reason):
        nonlocal score
        score+=delta
        factors.append({"factor":name,"impact":delta,"reason":reason})
    if exact_email: apply("exact_email",-28,"Exact email string is stronger evidence; mailbox ownership is not verified.")
    if exact_phone: apply("exact_phone",-18,"Exact normalized phone string is stronger evidence; subscriber ownership is not verified.")
    if cross_linked_profile: apply("cross_linked_profile",-22,"A public profile explicitly links to another identifier.")
    if independent_sources: apply("independent_sources",-min(18,6*min(independent_sources,3)),f"{independent_sources} independent source(s) corroborate the lead.")
    if contradictions: apply("contradictions",min(35,15*contradictions),"Conflicting attributes increase false-match concern.")
    if popular_handle: apply("popular_handle",15,"Common handles are weak identifiers.")
    if display_name_only: apply("display_name_only",22,"Display-name similarity alone is not identity evidence.")
    if stale_sources: apply("stale_sources",min(15,5*stale_sources),"Older evidence may no longer describe the same account.")
    score=max(5,min(100,score))
    band="low" if score<30 else "moderate" if score<60 else "high"
    return RiskAssessment(score,band,"Higher score means higher false-positive concern",factors)

def assess_evidence_risk(evidence: list[Any]) -> RiskAssessment:
    """Derive transparent triage factors from actual case evidence records."""
    rows=list(evidence or [])
    combined="\n".join(" ".join(str(getattr(x,k,"") or "") for k in ("title","url","content")) for x in rows)
    email=bool(re.search(r"(?<![\w.+-])[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}(?![\w.-])",combined))
    phone=bool(re.search(r"(?<!\w)\+\d[\d\s().-]{7,}\d(?!\w)",combined))
    explicit_links=any("rel=me" in str(getattr(x,"content","")).lower() or "links to" in str(getattr(x,"content","")).lower() for x in rows)
    sources={str(getattr(x,"source","")).strip().casefold() for x in rows if str(getattr(x,"source","")).strip()}
    sources.discard("")
    names=[str(getattr(x,"title","")).casefold().strip() for x in rows if getattr(x,"title",None)]
    contradictions=1 if len(set(names))>1 and any(term in combined.casefold() for term in ("conflict","contradict","different owner","not the same")) else 0
    stale=sum(1 for x in rows if str(getattr(x,"observed_at","")).startswith(("2018","2019","2020","2021")))
    return assess_false_positive_risk(exact_email=email,exact_phone=phone,
        cross_linked_profile=explicit_links,independent_sources=max(0,len(sources)-1),
        contradictions=contradictions,display_name_only=bool(names) and not (email or phone or explicit_links),
        stale_sources=stale)

def calibration_status(labeled_examples: int) -> str:
    if labeled_examples < 100: return "uncalibrated: at least 100 labeled examples required before calibration is considered"
    return "calibration_candidate: validate with held-out data and report calibration metrics before showing probability"
