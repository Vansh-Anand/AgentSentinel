"""Execute the portable evaluation notebook and retain its real outputs."""
from pathlib import Path

import nbformat
from nbconvert.preprocessors import ExecutePreprocessor


ROOT = Path(__file__).resolve().parents[1]
NOTEBOOK = ROOT / "notebooks" / "AgentSentinel_Portable_Evaluation.ipynb"


def main() -> None:
    value = nbformat.read(NOTEBOOK, as_version=4)
    ExecutePreprocessor(timeout=600, kernel_name="python3").preprocess(
        value, {"metadata": {"path": str(ROOT)}}
    )
    nbformat.write(value, NOTEBOOK)
    print(f"Executed {NOTEBOOK}")


if __name__ == "__main__":
    main()
