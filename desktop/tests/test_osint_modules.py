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
    bundle=json.loads((tmp_path/"x.stix.json").read_text())
    assert bundle["objects"][1]["type"]=="note"
    assert any(obj["type"]=="indicator" and "url:value" in obj.get("pattern","") for obj in bundle["objects"])

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

def test_pdf_export(tmp_path):
    from smartintel.exports import export_pdf
    item=[{"title":"PDF check","source":"test","content":"evidence"}]
    path=tmp_path/"report.pdf"
    export_pdf("test case",item,str(path))
    assert path.exists() and path.stat().st_size > 100


def test_all_in_one_scan_continues_and_normalizes_findings(monkeypatch):
    from types import SimpleNamespace
    from smartintel.collectors import all_in_one as scan
    from smartintel.collectors import passive_sources as sources
    monkeypatch.setattr(scan,"collect_domain",lambda domain:[SimpleNamespace(title="DNS",value="8.8.8.8",source="DNS",url="",confidence="High")])
    monkeypatch.setattr(sources,"certificate_transparency",lambda domain: (_ for _ in ()).throw(RuntimeError("API key not configured")))
    monkeypatch.setattr(sources,"wayback",lambda target: {"title":"Archive","content":"capture","source":"Wayback","url":"https://archive.org","confidence":"High"})
    for name in ("virustotal_domain","urlscan_search","otx_domain","passive_dns_history","gdelt_news"):
        monkeypatch.setattr(sources,name,lambda *args: (_ for _ in ()).throw(RuntimeError("API key not configured")))
    result=scan.run_all("example.org")
    assert result["findings"][0]["title"]=="DNS"
    assert result["findings"][0]["content"]=="8.8.8.8"
    assert any("Certificate transparency" in item for item in result["skipped"])
    assert any(item["title"]=="Archive" for item in result["findings"])

def test_all_in_one_scan_rejects_private_ip():
    import pytest
    from smartintel.collectors.all_in_one import run_all
    with pytest.raises(ValueError):
        run_all("192.168.1.1")


def test_all_in_one_supports_username_and_email_safe_paths(monkeypatch):
    from smartintel.collectors import all_in_one as scan
    from smartintel.collectors import passive_sources as sources
    seen=[]
    monkeypatch.setattr(sources,"public_username_reference",lambda value: seen.append(("username",value)) or {"title":"Username references","content":"{}","source":"Public references","url":"","confidence":"Low"})
    monkeypatch.setattr(sources,"breach_check_guidance",lambda value: seen.append(("email",value)) or {"title":"Breach workflow guidance","content":"{}","source":"Authorized workflow","url":"","confidence":"Low"})
    username=scan.run_all("@example_user")
    email=scan.run_all("analyst@example.org")
    assert seen==[("username","@example_user"),("email","analyst@example.org")]
    assert username["findings"][0]["title"]=="Username references"
    assert email["findings"][0]["title"]=="Breach workflow guidance"


def test_audit_journal_is_real_jsonl_and_refuses_corrupt_append(tmp_path):
    import pytest
    from smartintel.evidence_integrity import append_audit, verify_audit
    journal=tmp_path/"audit.jsonl"
    append_audit(journal,{"action":"first"})
    append_audit(journal,{"action":"second"})
    assert len(journal.read_text(encoding="utf-8").splitlines())==2
    assert verify_audit(journal)==(True,2)
    journal.write_text(journal.read_text(encoding="utf-8")+"not-json\\n",encoding="utf-8")
    assert verify_audit(journal)==(False,2)
    with pytest.raises(ValueError):
        append_audit(journal,{"action":"must-not-append"})


def test_stix_note_content_uses_real_newlines(tmp_path):
    import json
    from smartintel.exports import export_stix
    path=tmp_path/"evidence.stix.json"
    export_stix([{"title":"Finding","source":"Unit test","url":"https://example.org","confidence":"High","content":"Body text"}],path)
    bundle=json.loads(path.read_text(encoding="utf-8"))
    note=next(obj for obj in bundle["objects"] if obj["type"]=="note")
    assert r"\n" not in note["content"]
    assert "\nSource: Unit test\nURL: https://example.org" in note["content"]
