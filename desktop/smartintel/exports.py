"""JSON, CSV, STIX 2.1 note-bundle and DOCX export helpers."""
import csv,json,uuid
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
        objects.append({"type":"note","spec_version":"2.1","id":"note--"+str(uuid.uuid4()),"created":now,"modified":now,"content":f"{item.get('title','Finding')}\\nSource: {item.get('source','')}\\nURL: {item.get('url','')}\\nConfidence: {item.get('confidence','Unknown')}\\n\\n{item.get('content','')}","abstract":item.get("title","OSINT observation"),"authors":["Smart Intel analyst"],"object_refs":[identity["id"]]})
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
