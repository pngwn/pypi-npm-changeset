import argparse
import json
import sys
import urllib.request
from pathlib import Path

locs = {
  "gradio_client": Path(__file__).parent / "client" / "python" / "version.txt",
  "gradio": Path(__file__).parent / "gradio" / "version.txt",
}

mods = {
  "gradio_client": "gradio-test-client-pypi",
  "gradio": "gradio-test-pypi",
}

parser = argparse.ArgumentParser(description='Check a module has been deployed to pypi')
parser.add_argument('--name', type=str, default="gradio")
args = parser.parse_args()

path_to_version = locs.get(args.name, "Not found")
pypi_module = mods.get(args.name, "Not found")
version = path_to_version.read_text(encoding="utf8").strip()
releases = None

try:
  with urllib.request.urlopen(f"https://pypi.org/pypi/{pypi_module}/json") as url:
      print(url)
      releases = json.load(url)["releases"]
except urllib.error.HTTPError as e:
  if e.code == 404:
    print(f"Module {pypi_module} does not exist on PyPI")


if releases and version in releases:
    print(f"Version {version} already exists on PyPI")
    sys.exit(1)
else:
    print(f"Version {version} does not exist on PyPI")

