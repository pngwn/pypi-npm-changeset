import pkgutil

import gradio.util as util

current_pkg_version = (
    (pkgutil.get_data(__name__, "version.txt") or b"").decode("ascii").strip()
)
__version__ = current_pkg_version

print(__version__, __name__)