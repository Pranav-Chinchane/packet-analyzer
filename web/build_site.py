"""Builds the online version into _site. Needs Emscripten (em++).

Usage: python web/build_site.py
Then:  python -m http.server 8090 --directory _site
"""
import os
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "_site"
CSP = ("default-src 'none'; style-src 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; "
       "connect-src 'self'; font-src 'self'; img-src data:; worker-src 'self'; base-uri 'none'; form-action 'none'")
THREADED = {"main_mt.cpp", "fast_path.cpp", "load_balancer.cpp", "dpi_engine.cpp"}

shutil.rmtree(SITE, ignore_errors=True)
(SITE / "fonts").mkdir(parents=True)
sources = sorted(str(p.relative_to(ROOT).as_posix()) for p in (ROOT / "src").glob("*.cpp") if p.name not in THREADED)
compiler = os.environ.get("EMXX") or shutil.which("em++")
if not compiler:
    raise SystemExit("em++ was not found. Install Emscripten first.")
subprocess.run([compiler, "-std=c++17", "-O2", "-Wall", "-Wextra", "-I", "include", *sources, "-o", str(SITE / "engine.js"),
                "-sMODULARIZE", "-sEXPORT_NAME=createEngine", "-sENVIRONMENT=worker", "-sINVOKE_RUN=0", "-sEXIT_RUNTIME=0",
                "-sALLOW_MEMORY_GROWTH", "-sFORCE_FILESYSTEM", "-sEXPORTED_RUNTIME_METHODS=callMain,FS"], cwd=ROOT, check=True)

page = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")
marker = '<meta name="engine" content="server">'
if marker not in page:
    raise SystemExit("engine marker not found in ui/index.html")
page = page.replace(marker, f'<meta http-equiv="Content-Security-Policy" content="{CSP}">\n<meta name="engine" content="browser">')
(SITE / "index.html").write_text(page, encoding="utf-8", newline="\n")
for source, target in [("ui/icons.js", "icons.js"), ("web/worker.js", "worker.js"), ("data/sample_traffic.pcap", "sample_traffic.pcap"),
                       ("ui/fonts/schibsted-grotesk.woff2", "fonts/schibsted-grotesk.woff2"), ("ui/fonts/LICENSE.txt", "fonts/LICENSE.txt")]:
    shutil.copyfile(ROOT / source, SITE / target)
print("Built", SITE)
