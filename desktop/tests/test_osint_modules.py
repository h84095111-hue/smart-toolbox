import json
from smartintel.analysis.insights import deduplicate, source_credibility, risk_score, entity_edges
from smartintel.evidence_integrity import append_audit, verify_audit
from smartintel.exports import export_json, export_csv, export_stix

def test_audit_chain_detects_tampering(tmp_path):
    p=tmp_path/'audit.jsonl'
    append_audit(p,{"action":"case_created"}); append_audit(p,{"action":"evidence_added"})
    assert verify_audit(p)==(True,2)
    rows=p.read_text().splitlines(); item=json.loads(rows[0]); item['event']['action']='tampered'; rows[0]=json.dumps(item); p.write_text('\n'.join(rows)+'\n')
    assert verify_audit(p)[0] is False

def test_dedup_and_credibility():
    rows=[{"title":"A","source":"ICANN RDAP","url":"https://x","content":"1"}]*2
    assert len(deduplicate(rows))==1
    assert source_credibility("ICANN RDAP")["heuristic_score"] > source_credibility("user input")["heuristic_score"]

def test_risk_score_is_explainable():
    result=risk_score([{"label":"phishing","source":"test"}])
    assert result["score"]==30 and result["reasons"]
    assert "does not mean safe" in result["caveat"]

def test_entity_extract_rejects_private_ip():
    nodes=entity_edges("host example.org and 8.8.8.8 and 127.0.0.1")
    values={x["value"] for x in nodes}
    assert "example.org" in values and "8.8.8.8" in values and "127.0.0.1" not in values

def test_exports(tmp_path):
    evidence=[{"title":"Example","source":"Test","url":"https://example.org","content":"hello","confidence":"High"}]
    export_json({"name":"case"},evidence,str(tmp_path/"x.json"))
    export_csv(evidence,str(tmp_path/"x.csv"))
    export_stix(evidence,str(tmp_path/"x.stix.json"))
    assert json.loads((tmp_path/"x.json").read_text())["evidence"][0]["title"]=="Example"
    assert json.loads((tmp_path/"x.stix.json").read_text())["objects"][1]["type"]=="note"

def test_username_lookup_is_reference_only():
    from smartintel.collectors.passive_sources import public_username_reference
    result=public_username_reference("@example_user")
    payload=json.loads(result["content"])
    assert result["confidence"]=="Low"
    assert "github.com/example_user" in payload["links"]["GitHub"]
    assert "ownership is verified" in payload["note"]

def test_breach_workflow_does_not_fetch_leaked_data():
    from smartintel.collectors.passive_sources import breach_check_guidance
    result=breach_check_guidance("security@example.org")
    payload=json.loads(result["content"])
    assert payload["status"]=="Not queried"
    assert "does not retrieve" in payload["privacy"]

def test_provider_ip_lookup_rejects_private_targets():
    from smartintel.collectors.passive_sources import _public_ip
    import pytest
    with pytest.raises(ValueError):
        _public_ip("192.168.1.10")
