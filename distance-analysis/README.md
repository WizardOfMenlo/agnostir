# Distance analysis

`era.py`, `basefold.py`, and `brakedown.py` implement the numerical distance
calculations used by the experiments. Brakedown follows Habock's analysis.
Install the root `requirements-analysis.txt` to run these scripts and
`test_distances.py`.

## Interactive exponent notebook

[exponent-behavior.ipynb](exponent-behavior.ipynb) is the Jupyter notebook
referenced in the paper's discussion of the second candidate distance in
CalcDist. It visualizes the stationary value of `d0`, the normalized
permutation exponent, and its component terms as `d1` varies, with sliders
for `delta`, `c`, and `r`.

From the repository root:

```sh
python3 -m venv /tmp/era-codes-notebook
source /tmp/era-codes-notebook/bin/activate
python -m pip install -r distance-analysis/requirements-notebook.txt
python -m jupyter lab distance-analysis/exponent-behavior.ipynb
```

Select the **Python 3 (ipykernel)** kernel and run all cells from top to bottom.
SageMath is not needed. Jupyter and the plotting/widget packages are optional;
the benchmark Docker image and offline dependency archive contain only the
NumPy/SciPy requirements needed for distance calibration.

The original calculation and plotting cells are unchanged from the old
`era-code-analysis` repository's `exponent-behavior.ipynb` (file commit
`5f9b4c3cdb93dfe59c2a837d2eb06e5a7f175c6c`). The migration adds an introductory
Markdown cell and replaces the SageMath kernel metadata with Python 3.
The original file SHA-256 is
`e71538eae2458d3d8a29de203a68fa9546c35126f715df69f04859a9af2f9247`.

This notebook illustrates the exponent's behavior; its slider ranges and root
search do not enforce all the finite-length and field-size conditions in
CalcDist. Use `era.py` and the distance checks for experiment parameters.
