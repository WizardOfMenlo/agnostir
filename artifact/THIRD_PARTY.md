# Third-party software

The MIT license at the root covers the authors' project code. It does not
relicense dependencies, their bundled code, or the supplied paper PDF.
The PDF is supplied for artifact evaluation; copyright remains with its authors.

Rust dependencies are recorded with exact versions, source URLs/commit IDs,
and their declared SPDX licenses in `artifact/rust-dependencies.json`.
The Cargo.lock file is authoritative for resolution. Plonky3 is pinned to the
commit resolved from `a9d5bbb`; its source is used unmodified. Arkworks supplies
the secp256k1 scalar field; BLAKE3 supplies hashing; Rayon supplies parallelism.

The optional dependency archive includes complete Cargo vendor directories
and their original license notices. `dependencies/licenses/` adds upstream
workspace notices for git packages whose vendored crate folders omit them.
Copies of discovered license/copyright notices are also included under
`artifact/dependency-licenses/` in the main submission, indexed by dependency. Where upstream distributions provide only license
declarations in README files, those original notices are retained alongside
the SPDX declarations. The inventory does not substitute a new license for
the upstream terms.

Python dependencies are NumPy 2.4.1 and SciPy 1.17.0. The optional Linux/CPython
3.11 wheels contain their licenses and the notices for bundled numerical
libraries. Their exact filenames and SHA-256 values are recorded in the
dependency manifest. Python package metadata declares BSD-family licensing;
consult the included full notices for bundled components.

The Dockerfile fetches the pinned official Rust/Debian base and Debian packages
from their distributors. The main artifact does not redistribute that OS image.
System package versions and compiler/Python versions from the tested image are
retained with container validation logs. Building requires network access for
those OS packages even when the language dependency archive is supplied.
