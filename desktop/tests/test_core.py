import pytest
from smartintel.storage import Store
from smartintel.models import Evidence
from smartintel.collectors.passive import collect_ip

def test_case_and_evidence_roundtrip(tmp_path):
    store=Store(tmp_path/'test.sqlite3')
    case_id=store.create_case('Example investigation')
    item=Evidence(case_id,'Test source','Example finding','https://example.com','sample')
    store.add_evidence(item)
    assert store.cases()[0]['name']=='Example investigation'
    found=store.evidence(case_id)
    assert len(found)==1
    assert found[0].title=='Example finding'
    assert found[0].content=='sample'

@pytest.mark.parametrize('address',['127.0.0.1','10.0.0.1','192.168.1.1','::1'])
def test_non_public_ip_is_rejected(address):
    with pytest.raises(ValueError):
        collect_ip(address)
