import sys, json, base64, hashlib, secrets, string, uuid, html
from datetime import datetime, timezone
from urllib.parse import quote, unquote
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QPixmap
from PyQt6.QtWidgets import *

TOOLS=[
("Password generator","Security","Create a strong random password"),
("QR code generator","Generator","Make and save a QR code"),
("JSON formatter","Developer","Format, validate and minify JSON"),
("Base64 converter","Developer","Encode and decode UTF-8 text"),
("URL encoder","Developer","Encode or decode URL components"),
("SHA-256 hash","Security","Create a SHA-256 digest"),
("Text toolkit","Writing","Count and transform text"),
("Unit converter","Everyday","Convert length, weight and temperature"),
("UUID generator","Developer","Generate UUID version 4 identifiers"),
("Color converter","Design","Pick colors and view HEX, RGB, HSL"),
("Timestamp converter","Developer","Convert Unix timestamps to UTC"),
("Markdown helper","Writing","Write and preview Markdown")]

CSS="""QWidget{background:#101827;color:#e8edf7;font-family:'Segoe UI',Arial;font-size:13px}
QMainWindow{background:#0b1220} QFrame#side{background:#101a2b;border-right:1px solid #293950}
QLabel#brand{font-size:19px;font-weight:800;padding:12px 4px 25px}
QLabel#hero{font-size:26px;font-weight:800;color:#f4f5ff;padding:12px 0}
QLabel#muted{color:#91a0b7} QLabel#section{color:#8594ab;font-size:10px;font-weight:700;padding:12px 4px}
QPushButton{background:#202e45;border:1px solid #34445e;border-radius:8px;padding:10px;color:#dce5f4;text-align:left}
QPushButton:hover{border-color:#8179fa;background:#283552} QPushButton:checked{background:#302e62;border-color:#8179fa}
QPushButton#go{background:#7168ed;border:1px solid #8b84ff;color:white;font-weight:700;text-align:center}
QLineEdit,QTextEdit,QComboBox,QSpinBox{background:#0b1525;border:1px solid #30405a;border-radius:7px;padding:9px;color:#e8edf7}
QTextEdit{min-height:100px} QComboBox QAbstractItemView{background:#152239;selection-background-color:#514cb0}
QCheckBox{spacing:8px;color:#bdc9dc} QTextBrowser{background:#0b1525;border:1px solid #30405a;border-radius:8px;padding:10px}
"""

class App(QMainWindow):
 def __init__(self):
  super().__init__(); self.setWindowTitle("Smart Toolbox — Desktop"); self.resize(1120,760); self.setMinimumSize(850,600)
  root=QWidget(); row=QHBoxLayout(root); row.setContentsMargins(0,0,0,0); row.setSpacing(0)
  side=QFrame(); side.setObjectName("side"); side.setFixedWidth(245); sv=QVBoxLayout(side); sv.setContentsMargins(16,20,16,16)
  brand=QLabel("✦  SMART TOOLBOX"); brand.setObjectName("brand"); sv.addWidget(brand)
  label=QLabel("YOUR WORKSPACE"); label.setObjectName("section"); sv.addWidget(label)
  self.nav=[]
  for i,(name,cat,desc) in enumerate(TOOLS):
   b=QPushButton("  "+name); b.setCheckable(True); b.clicked.connect(lambda checked=False,n=i:self.select(n)); sv.addWidget(b); self.nav.append(b)
  sv.addStretch(); privacy=QLabel("●  PRIVATE BY DESIGN\n   Your data stays on this device."); privacy.setStyleSheet("color:#83dfbb;background:#17263a;padding:13px;border:1px solid #30405a;border-radius:8px;font-size:11px"); sv.addWidget(privacy); row.addWidget(side)
  main=QWidget(); mv=QVBoxLayout(main); mv.setContentsMargins(28,22,28,16); mv.setSpacing(13)
  top=QHBoxLayout(); crumb=QLabel("Workspace  /  All tools"); crumb.setObjectName("muted"); top.addWidget(crumb); top.addStretch()
  self.search=QLineEdit(); self.search.setPlaceholderText("Search tools..."); self.search.setMaximumWidth(240); self.search.textChanged.connect(self.filter); top.addWidget(self.search); mv.addLayout(top)
  hero=QLabel("The tools you need. Nothing you don't.\nA collection of fast, practical desktop utilities."); hero.setObjectName("hero"); hero.setStyleSheet("background:#171f38;border:1px solid #31365e;border-radius:12px;padding:18px"); mv.addWidget(hero)
  self.title=QLabel(); self.title.setStyleSheet("font-size:21px;font-weight:750"); mv.addWidget(self.title)
  self.desc=QLabel(); self.desc.setObjectName("muted"); mv.addWidget(self.desc)
  self.form=QWidget(); self.form_layout=QVBoxLayout(self.form); self.form_layout.setContentsMargins(0,0,0,0); self.form_layout.setSpacing(10); mv.addWidget(self.form,1)
  foot=QLabel("© 2026 Smart Toolbox  •  Local desktop app — no cloud account required"); foot.setObjectName("muted"); mv.addWidget(foot)
  row.addWidget(main,1); self.setCentralWidget(root); self.select(0)
 def filter(self,text):
  q=text.casefold()
  for i,b in enumerate(self.nav): b.setVisible(not q or q in (TOOLS[i][0]+TOOLS[i][1]+TOOLS[i][2]).casefold())
 def clear(self):
  while self.form_layout.count():
   item=self.form_layout.takeAt(0); w=item.widget()
   if w:w.deleteLater()
 def label(self,t):
  x=QLabel(t.upper()); x.setStyleSheet("color:#9aa9c0;font-size:10px;font-weight:700;letter-spacing:1px"); return x
 def editor(self,t="",h=120):
  x=QTextEdit(); x.setPlainText(t); x.setMinimumHeight(h); return x
 def addfield(self,t,w): self.form_layout.addWidget(self.label(t)); self.form_layout.addWidget(w)
 def button(self,t,fn,primary=False):
  b=QPushButton(t); b.clicked.connect(fn)
  if primary:b.setObjectName("go")
  return b
 def row(self,*widgets):
  r=QHBoxLayout()
  for w in widgets:r.addWidget(w)
  self.form_layout.addLayout(r)
 def output(self):
  self.out=self.editor("Your result will appear here...",95); self.out.setReadOnly(True); self.addfield("RESULT",self.out)
 def copy(self):
  QApplication.clipboard().setText(self.out.toPlainText()); self.statusBar().showMessage("Copied to clipboard",2200)
 def select(self,n):
  self.clear(); self.index=n
  for i,b in enumerate(self.nav):b.setChecked(i==n)
  name,cat,desc=TOOLS[n]; self.title.setText(name); self.desc.setText(desc)
  getattr(self,"tool_"+str(n))()
 def tool_0(self):
  length=QSpinBox(); length.setRange(8,128); length.setValue(20); self.addfield("PASSWORD LENGTH",length)
  opts=[]
  for s in ["Uppercase letters","Lowercase letters","Numbers","Symbols"]:
   c=QCheckBox(s); c.setChecked(True); self.form_layout.addWidget(c); opts.append(c)
  self.output()
  def go():
   groups=[string.ascii_uppercase,string.ascii_lowercase,string.digits,"!@#$%^&*()-_=+[]{};:,.?"]
   chars="".join(g for g,c in zip(groups,opts) if c.isChecked())
   if not chars:QMessageBox.warning(self,"Select options","Choose at least one character group.");return
   self.out.setPlainText("".join(secrets.choice(chars) for _ in range(length.value())))
  self.row(self.button("✦ Generate password",go,True),self.button("Copy",self.copy))
 def tool_1(self):
  src=self.editor("https://example.com",65); self.addfield("TEXT OR URL",src); preview=QLabel("QR preview appears here"); preview.setAlignment(Qt.AlignmentFlag.AlignCenter); preview.setMinimumHeight(190); preview.setStyleSheet("background:#f2f4f8;color:#26344a;border-radius:8px"); self.form_layout.addWidget(preview); self.qr=None
  def make():
   try:
    import qrcode,io
    img=qrcode.make(src.toPlainText()); buf=io.BytesIO(); img.save(buf,format="PNG"); self.qr=buf.getvalue(); pix=QPixmap();pix.loadFromData(self.qr);preview.setPixmap(pix.scaled(190,190,Qt.AspectRatioMode.KeepAspectRatio,Qt.TransformationMode.SmoothTransformation))
   except ImportError:QMessageBox.warning(self,"Missing package","Run pip install -r requirements.txt")
  def save():
   if not self.qr:make()
   if self.qr:
    p,_=QFileDialog.getSaveFileName(self,"Save QR","smart-toolbox-qr.png","PNG (*.png)")
    if p:open(p,"wb").write(self.qr)
  self.row(self.button("Generate QR",make,True),self.button("Save PNG",save))
 def tool_2(self):
  src=self.editor('{\n  "name": "Smart Toolbox",\n  "ready": true\n}',150);self.addfield("INPUT JSON",src);self.output()
  def run(pretty):
   try:self.out.setPlainText(json.dumps(json.loads(src.toPlainText()),indent=2 if pretty else None,ensure_ascii=False))
   except Exception as e:self.out.setPlainText("Invalid JSON: "+str(e))
  self.row(self.button("Format JSON",lambda:run(True),True),self.button("Minify",lambda:run(False)),self.button("Copy",self.copy))
 def tool_3(self):
  src=self.editor("Hello, world!");self.addfield("INPUT TEXT",src);self.output()
  def enc():
   try:self.out.setPlainText(base64.b64encode(src.toPlainText().encode()).decode())
   except Exception as e:self.out.setPlainText(str(e))
  def dec():
   try:self.out.setPlainText(base64.b64decode(src.toPlainText(),validate=True).decode())
   except Exception as e:self.out.setPlainText("Invalid Base64: "+str(e))
  self.row(self.button("Encode",enc,True),self.button("Decode",dec),self.button("Copy",self.copy))
 def tool_4(self):
  src=self.editor("https://example.com/search?q=hello world");self.addfield("INPUT",src);self.output()
  self.row(self.button("Encode",lambda:self.out.setPlainText(quote(src.toPlainText(),safe="")),True),self.button("Decode",lambda:self.out.setPlainText(unquote(src.toPlainText()))),self.button("Copy",self.copy))
 def tool_5(self):
  src=self.editor("Hello, world!");self.addfield("TEXT TO HASH",src);self.output()
  self.row(self.button("Generate SHA-256",lambda:self.out.setPlainText(hashlib.sha256(src.toPlainText().encode()).hexdigest()),True),self.button("Copy",self.copy))
 def tool_6(self):
  src=self.editor("The quick brown fox jumps over the lazy dog.");self.addfield("YOUR TEXT",src);stats=QLabel();stats.setStyleSheet("color:#aaa4ff;font-weight:700");self.form_layout.addWidget(stats)
  def update():
   t=src.toPlainText();stats.setText(f"Words: {len(t.split())}     Characters: {len(t)}     Lines: {len(t.splitlines()) or 1}")
  src.textChanged.connect(update);update()
  self.row(self.button("UPPERCASE",lambda:src.setPlainText(src.toPlainText().upper())),self.button("lowercase",lambda:src.setPlainText(src.toPlainText().lower())),self.button("Clean spaces",lambda:src.setPlainText(" ".join(src.toPlainText().split()))),self.button("Copy",lambda:QApplication.clipboard().setText(src.toPlainText())))
 def tool_7(self):
  kind=QComboBox();kind.addItems(["Length","Weight","Temperature"]);val=QLineEdit("1");a=QComboBox();b=QComboBox()
  units={"Length":["meter","kilometer","centimeter","mile","foot"],"Weight":["gram","kilogram","pound","ounce"],"Temperature":["Celsius","Fahrenheit"]}
  factors={"Length":{"meter":1,"kilometer":1000,"centimeter":.01,"mile":1609.344,"foot":.3048},"Weight":{"gram":1,"kilogram":1000,"pound":453.59237,"ounce":28.3495}}
  self.addfield("TYPE",kind);self.addfield("VALUE",val);self.row(a,b);result=QLabel("—");result.setStyleSheet("font-size:24px;font-weight:700;color:#aaa4ff;padding:12px");self.form_layout.addWidget(result)
  def change():
   a.clear();b.clear();a.addItems(units[kind.currentText()]);b.addItems(units[kind.currentText()]);b.setCurrentIndex(min(1,b.count()-1))
  kind.currentTextChanged.connect(change);change()
  def go():
   try:
    n=float(val.text());k=kind.currentText();x=a.currentText();y=b.currentText()
    if k=="Temperature":c=n if x=="Celsius" else (n-32)*5/9;r=c if y=="Celsius" else c*9/5+32
    else:r=n*factors[k][x]/factors[k][y]
    result.setText(f"{r:.8g} {y}")
   except Exception:result.setText("Enter a valid value")
  self.row(self.button("Convert",go,True))
 def tool_8(self):
  self.output();self.row(self.button("Generate UUID",lambda:self.out.setPlainText(str(uuid.uuid4())),True),self.button("Copy",self.copy))
 def tool_9(self):
  swatch=QLabel(" ");swatch.setMinimumHeight(90);swatch.setStyleSheet("background:#7168ed;border-radius:8px");self.form_layout.addWidget(swatch);self.output()
  def choose():
   c=QColorDialog.getColor(QColor("#7168ed"),self,"Choose a color")
   if c.isValid():
    swatch.setStyleSheet(f"background:{c.name()};border-radius:8px")
    h,s,l=c.getHsl();self.out.setPlainText(f"HEX  {c.name().upper()}\nRGB  {c.red()}, {c.green()}, {c.blue()}\nHSL  {h}°, {round(s/2.55)}%, {round(l/2.55)}%")
  self.row(self.button("Choose color",choose,True),self.button("Copy values",self.copy))
 def tool_10(self):
  stamp=QLineEdit(str(int(datetime.now(timezone.utc).timestamp())));self.addfield("UNIX TIMESTAMP · SECONDS",stamp);self.output()
  def go():
   try:
    d=datetime.fromtimestamp(float(stamp.text()),timezone.utc);self.out.setPlainText(d.isoformat().replace("+00:00","Z")+"\n"+d.strftime("%A, %d %B %Y · %H:%M:%S UTC"))
   except Exception as e:self.out.setPlainText("Invalid timestamp: "+str(e))
  self.row(self.button("Convert timestamp",go,True),self.button("Copy",self.copy));go()
 def tool_11(self):
  src=self.editor("# Hello, world!\n\nWrite **bold** and *italic* text.\n\n- First item\n- Second item");self.addfield("MARKDOWN SOURCE",src);preview=QTextBrowser();preview.setMinimumHeight(150);self.addfield("PREVIEW",preview)
  def render():
   lines=[]
   for line in src.toPlainText().splitlines():
    x=html.escape(line)
    if x.startswith("# "):lines.append("<h2>"+x[2:]+"</h2>")
    elif x.startswith("## "):lines.append("<h3>"+x[3:]+"</h3>")
    elif x.startswith("- "):lines.append("<p>• "+x[2:]+"</p>")
    else:lines.append("<p>"+x+"</p>")
   preview.setHtml("<div style='color:#dce5f4'>"+ "".join(lines)+"</div>")
  src.textChanged.connect(render);render();self.form_layout.addWidget(self.button("Copy Markdown",lambda:QApplication.clipboard().setText(src.toPlainText())))

if __name__=="__main__":
 app=QApplication(sys.argv);app.setApplicationName("Smart Toolbox");app.setStyleSheet(CSS);w=App();w.show();sys.exit(app.exec())
