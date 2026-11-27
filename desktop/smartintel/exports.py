"""JSON, CSV, STIX 2.1 note-bundle and DOCX export helpers."""
import csv,json,uuid,re,ipaddress
from pathlib import Path
from datetime import datetime,timezone
def export_json(case,evidence,path):
    Path(path).write_text(json.dumps({"case":case,"evidence":evidence},indent=2,ensure_ascii=False,default=str),encoding="utf-8")
def export_csv(evidence,path):
    fields=["id","title","source","url","observed_at","confidence","kind","content"]
    with open(path,"w",newline="",encoding="utf-8-sig") as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction="ignore"); w.writeheader(); w.writerows(evidence)
def export_stix(evidence,path,case_name="Smart Intel case"):
    now=datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00","Z")
    identity={"type":"identity","spec_version":"2.1","id":"identity--"+str(uuid.uuid4()),"created":now,"modified":now,"name":"Smart Intel analyst","identity_class":"individual"}
    objects=[identity]
    for item in evidence:
        content=str(item.get("content","")); source_url=str(item.get("url",""))
        objects.append({"type":"note","spec_version":"2.1","id":"note--"+str(uuid.uuid4()),"created":now,"modified":now,"content":f"{item.get('title','Finding')}\nSource: {item.get('source','')}\nURL: {source_url}\nConfidence: {item.get('confidence','Unknown')}\n\n{content}","abstract":item.get("title","OSINT observation"),"authors":["Smart Intel analyst"],"object_refs":[identity["id"]]})
        candidates=[]
        for match in re.findall(r"https?://[^\s<>]+", source_url+" "+content):
            clean=match.rstrip(".,);]")
            if clean: candidates.append(("url",clean))
        for match in re.findall(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", source_url+" "+content):
            candidates.append(("domain",match.lower().rstrip(".")))
        for match in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", source_url+" "+content):
            try:
                if ipaddress.ip_address(match).is_global: candidates.append(("ipv4",match))
            except ValueError: pass
        seen=set()
        for kind,value in candidates:
            if (kind,value) in seen: continue
            seen.add((kind,value))
            if kind=="url": pattern=f"[url:value = '{value.replace(chr(39), chr(92)+chr(39))}']"
            elif kind=="domain": pattern=f"[domain-name:value = '{value}']"
            else: pattern=f"[ipv4-addr:value = '{value}']"
            objects.append({"type":"indicator","spec_version":"2.1","id":"indicator--"+str(uuid.uuid4()),"created":now,"modified":now,"name":f"Observed {kind}: {value}","description":"Extracted from collected evidence; not independently validated as malicious.","indicator_types":["unknown"],"pattern_type":"stix","pattern":pattern,"valid_from":now,"created_by_ref":identity["id"]})
    Path(path).write_text(json.dumps({"type":"bundle","id":"bundle--"+str(uuid.uuid4()),"objects":objects},indent=2,ensure_ascii=False),encoding="utf-8")
def export_docx(case_name,evidence,path):
    from docx import Document
    doc=Document(); doc.add_heading("Smart Intel — "+case_name,0)
    for item in evidence:
        doc.add_heading(item.get("title","Finding"),2)
        doc.add_paragraph("Source: "+item.get("source","")+" | Confidence: "+item.get("confidence","Unknown")+" | Observed: "+item.get("observed_at",""))
        if item.get("url"): doc.add_paragraph(item["url"])
        doc.add_paragraph(item.get("content",""))
    doc.save(path)

def export_pdf(case_name,evidence,path):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Preformatted, PageBreak
    from xml.sax.saxutils import escape
    doc=SimpleDocTemplate(path,pagesize=A4,rightMargin=18*mm,leftMargin=18*mm,topMargin=18*mm,bottomMargin=18*mm)
    styles=getSampleStyleSheet()
    styles.add(ParagraphStyle(name="EvidenceBody",parent=styles["BodyText"],fontName="Courier",fontSize=7,leading=9,wordWrap="CJK"))
    story=[Paragraph("Smart Intel — "+escape(case_name),styles["Title"]),Paragraph("Evidence items: "+str(len(evidence)),styles["Normal"]),Spacer(1,8*mm)]
    for item in evidence:
        story.append(Paragraph(escape(item.get("title","Finding")),styles["Heading2"]))
        meta="Source: "+item.get("source","")+" | Confidence: "+item.get("confidence","Unknown")+" | Observed: "+item.get("observed_at","")
        story.append(Paragraph(escape(meta),styles["Normal"]))
        if item.get("url"): story.append(Paragraph(escape(item["url"]),styles["Normal"]))
        story.append(Preformatted(item.get("content",""),styles["EvidenceBody"])); story.append(Spacer(1,5*mm))
    doc.build(story)
