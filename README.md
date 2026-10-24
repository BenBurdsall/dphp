# phpDetector

A small command-line tool that scans a file or directory and reports
anything that looks like PHP — either by file extension (`.php`, `.phtml`,
etc.) or by a `<?php` / `<?=` tag found in the file's content.

## Usage

```bash
python main.py [path]
```

If `path` is omitted, the current directory is scanned.

## Development

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pytest
```
