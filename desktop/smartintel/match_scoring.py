"""Transparent evidence-scoped triage; never a calibrated identity probability."""
from __future__ import annotations
from dataclasses import dataclass,asdict
from datetime import datetime,timezone
from typing import Any
import re
from urllib.parse import urlparse

@dataclass
class RiskAssessment:
    score:int
    risk_band:str
    label:str
    factors:list[dict]
    calibration:str="uncalibrated_heuristic"
    disclaimer:str="Heuristic triage index, not a statistically calibrated false-positive probability."
    def to_dict(self):return asdict(self)

def assess_false_positive_risk(*,exact_email=False,exact_phone=False,cross_linked_profile=False,
    independent_sources=0,contradictions=0,popular_handle=False,display_name_only=False,stale_sources=0):
    score=55; factors=[]
    def apply(name,delta,reason):
        nonlocal score
        score+=delta; factors.append({"factor":name,"impact":delta,"reason":reason})
    if exact_email:apply("exact_email",-28,"The selected email identifier is present in the supporting evidence; mailbox ownership remains unverified.")
    if exact_phone:apply("exact_phone",-18,"The selected phone identifier is present in the supporting evidence; subscriber ownership remains unverified.")
    if cross_linked_profile:apply("cross_linked_profile",-18,"The selected identifier is explicitly linked by a public profile attribute.")
    # Distinct source labels are not proof of source independence; do not award a bonus for them.
    if contradictions:apply("contradictions",min(35,15*contradictions),"Conflicting attributes increase false-match concern.")
    if popular_handle:apply("popular_handle",15,"Common handles are weak identifiers.")
    if display_name_only:apply("display_name_only",22,"Display-name similarity alone is not identity evidence.")
    if stale_sources:apply("stale_sources",min(20,5*stale_sources),"Evidence older than the rolling recency window may no longer describe the same account.")
    score=max(5,min(100,score)); band="low" if score<30 else "moderate" if score<60 else "high"
    return RiskAssessment(score,band,"Higher score means higher false-positive concern",factors)

def assess_evidence_risk(evidence:list[Any],subject:Any=None)->RiskAssessment:
    """Only award identifier support when the selected node's exact value occurs in its evidence."""
    rows=list(evidence or [])
    text="\n".join(" ".join(str(getattr(row,key,"") or "") for key in ("title","url","content")) for row in rows)
    normalized=text.casefold()
    kind=str(getattr(subject,"kind","") or "")
    label=str(getattr(subject,"label","") or "").strip()
    exact_email=kind=="email" and bool(label) and label.casefold() in normalized
    digits=lambda value:re.sub(r"\D","",str(value or ""))
    exact_phone=kind=="phone" and len(digits(label))>=8 and digits(label) in digits(text)
    cross_linked=False
    if label and kind in {"email","phone","username","profile_or_url"}:
        for row in rows:
            content=str(getattr(row,"content","") or "").casefold()
            if label.casefold() in content and ("rel=me" in content or "sameas" in content or "same_as" in content):
                cross_linked=True; break
    # Staleness uses a rolling 365-day window, not a hard-coded year range.
    cutoff=datetime.now(timezone.utc).timestamp()-365*24*60*60
    stale=0
    for row in rows:
        raw=str(getattr(row,"observed_at","") or "")
        try:
            stamp=datetime.fromisoformat(raw.replace("Z","+00:00"))
            if stamp.tzinfo is None:stamp=stamp.replace(tzinfo=timezone.utc)
            if stamp.timestamp()<cutoff:stale+=1
        except (ValueError,TypeError,OverflowError):continue
    # No cross-record source-count bonus: source labels do not establish independence.
    name_only=kind in {"source","username"} and bool(label) and not (exact_email or exact_phone or cross_linked)
    return assess_false_positive_risk(exact_email=exact_email,exact_phone=exact_phone,
        cross_linked_profile=cross_linked,display_name_only=name_only,stale_sources=stale)
