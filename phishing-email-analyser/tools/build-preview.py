"""
Builds a single-file copy of the site (dist/preview.html) with all CSS and JS inlined.
Only used to publish a preview on claude.ai. The real website is index.html + css/ + js/.
Run:  python3 tools/build-preview.py
"""
import re, pathlib
root = pathlib.Path(__file__).resolve().parent.parent
html = (root / 'index.html').read_text()
title = re.search(r'<title>.*?</title>', html).group(0)
body = html.split('<!--@@BODY_START@@-->')[1].split('<!--@@BODY_END@@-->')[0]
css = (root / 'css/styles.css').read_text()
scripts = re.findall(r'<script src="(js/[^"]+)"></script>', html)
js = '\n'.join((root / s).read_text() for s in scripts)
out = f"{title}\n<style>\n{css}\n</style>\n{body}\n<script>\n{js}\n</script>\n"
(root / 'dist').mkdir(exist_ok=True)
(root / 'dist/preview.html').write_text(out)
print('wrote dist/preview.html', len(out), 'bytes')
