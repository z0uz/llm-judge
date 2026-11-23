import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
SRC_DIR = ROOT_DIR / "src"
if SRC_DIR.is_dir() and str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

try:
    import spaces  # type: ignore

    # Required on ZeroGPU-hosted Spaces so the runtime registers cleanly without burning GPU quota.
    @spaces.GPU(duration=1)
    def _zerogpu_noop() -> None:
        return None
except ImportError:
    spaces = None

from llm_judge.ui import build_gradio_app, get_launch_kwargs  # noqa: E402

demo = build_gradio_app()


if __name__ == "__main__":
    demo.launch(**get_launch_kwargs(demo))
