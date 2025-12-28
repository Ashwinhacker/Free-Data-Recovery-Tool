import os, shutil, platform, threading, time, hashlib
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from collections import Counter
import csv

# Charts & PDF
import matplotlib.pyplot as plt
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

OS_NAME = platform.system()
scan_results = []
hash_map = {}

# ---------------- UI ---------------- #
app = tk.Tk()
app.title("Free Data Recovery Tool")
app.geometry("1150x700")

LIGHT_BG = "white"
DARK_BG = "#1e1e1e"
is_dark = False

def apply_theme():
    global is_dark
    bg = DARK_BG if is_dark else LIGHT_BG
    fg = "white" if is_dark else "black"
    app.configure(bg=bg)
    for w in app.winfo_children():
        try:
            w.configure(bg=bg, fg=fg)
        except:
            pass

# ---------------- Header ---------------- #
title = tk.Label(app, text=" DATA RECOVERY TOOL",
                 font=("Arial", 22, "bold"), fg="#0A74DA")
title.pack(pady=8)

info = tk.Label(app, text=f"OS Detected: {OS_NAME} | Logical Recovery + Analysis")
info.pack()

# ---------------- Controls ---------------- #
top = tk.Frame(app)
top.pack(pady=5)

file_type = tk.StringVar(value="ALL")
search_var = tk.StringVar()

ttk.Combobox(top, textvariable=file_type,
             values=["ALL", "PDF", "IMAGES", "VIDEOS", "DOCS", "ZIP", "AUDIO"],
             width=12, state="readonly").grid(row=0, column=0, padx=5)

tk.Entry(top, textvariable=search_var, width=25).grid(row=0, column=1, padx=5)
tk.Label(top, text="Search").grid(row=0, column=2)

tk.Button(top, text="🌗 Toggle Theme",
          command=lambda: toggle_theme()).grid(row=0, column=3, padx=10)

progress = ttk.Progressbar(app, length=700)
progress.pack(pady=5)

# ---------------- Table ---------------- #
cols = ("File", "Path", "Size(KB)", "Type", "MD5", "SHA256")
tree = ttk.Treeview(app, columns=cols, show="headings", height=16)
for c in cols:
    tree.heading(c, text=c)
    tree.column(c, width=180)
tree.pack(pady=8)

# ---------------- File Types ---------------- #
EXT = {
    "PDF": [".pdf"],
    "IMAGES": [".jpg", ".png", ".jpeg"],
    "VIDEOS": [".mp4", ".avi"],
    "DOCS": [".doc", ".docx", ".txt"],
    "ZIP": [".zip", ".rar"],
    "AUDIO": [".mp3", ".wav"]
}

# ---------------- Core Functions ---------------- #
def get_hash(path):
    md5 = hashlib.md5()
    sha = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while chunk := f.read(4096):
                md5.update(chunk)
                sha.update(chunk)
        return md5.hexdigest(), sha.hexdigest()
    except:
        return "ERR", "ERR"

def scan(folder):
    scan_results.clear()
    hash_map.clear()
    tree.delete(*tree.get_children())
    progress["value"] = 0

    all_files = []
    for root, _, files in os.walk(folder):
        for f in files:
            p = os.path.join(root, f)
            ext = os.path.splitext(f)[1].lower()
            if file_type.get() != "ALL" and ext not in EXT.get(file_type.get(), []):
                continue
            all_files.append(p)

    total = len(all_files)
    for i, path in enumerate(all_files):
        time.sleep(0.002)
        size = os.path.getsize(path)//1024
        md5, sha = get_hash(path)

        hash_map.setdefault(md5, []).append(path)

        data = (os.path.basename(path), path, size, ext, md5, sha)
        scan_results.append(data)
        tree.insert("", "end", values=data)
        progress["value"] = (i/total)*100

    messagebox.showinfo("Scan Complete", f"{len(scan_results)} files scanned")

def start_scan():
    folder = filedialog.askdirectory()
    if folder:
        threading.Thread(target=scan, args=(folder,), daemon=True).start()

# ---------------- Features ---------------- #
def recover():
    dest = filedialog.askdirectory()
    for i in tree.selection():
        shutil.copy(tree.item(i)["values"][1], dest)
    messagebox.showinfo("Recovery", "Files Recovered")

def select_all():
    for i in tree.get_children():
        tree.selection_add(i)

def deselect_all():
    tree.selection_remove(tree.selection())

def export_csv():
    f = filedialog.asksaveasfilename(defaultextension=".csv")
    with open(f, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(cols)
        writer.writerows(scan_results)
    messagebox.showinfo("Export", "CSV Exported")

def export_pdf():
    f = filedialog.asksaveasfilename(defaultextension=".pdf")
    c = canvas.Canvas(f, pagesize=A4)
    y = 800
    c.drawString(50, y, "Scan Report")
    y -= 20
    for r in scan_results[:40]:
        c.drawString(50, y, f"{r[0]} | {r[3]} | {r[2]}KB")
        y -= 15
    c.save()
    messagebox.showinfo("Export", "PDF Exported")

def pie_chart():
    types = [r[3] for r in scan_results]
    count = Counter(types)
    plt.pie(count.values(), labels=count.keys(), autopct="%1.1f%%")
    plt.title("Scan Statistics")
    plt.show()

def find_duplicates():
    dups = [v for v in hash_map.values() if len(v) > 1]
    messagebox.showinfo("Duplicates Found", f"{len(dups)} duplicate groups")

def toggle_theme():
    global is_dark
    is_dark = not is_dark
    apply_theme()

# ---------------- Buttons ---------------- #
btn = tk.Frame(app)
btn.pack(pady=8)

tk.Button(btn, text="Scan Folder", width=15, command=start_scan).grid(row=0, column=0, padx=5)
tk.Button(btn, text="Recover", width=15, command=recover).grid(row=0, column=1, padx=5)
tk.Button(btn, text="Select All", command=select_all).grid(row=0, column=2)
tk.Button(btn, text="Deselect", command=deselect_all).grid(row=0, column=3)
tk.Button(btn, text="Pie Chart", command=pie_chart).grid(row=0, column=4)
tk.Button(btn, text="Duplicates", command=find_duplicates).grid(row=0, column=5)
tk.Button(btn, text="Export CSV", command=export_csv).grid(row=0, column=6)
tk.Button(btn, text="Export PDF", command=export_pdf).grid(row=0, column=7)

apply_theme()
app.mainloop()
