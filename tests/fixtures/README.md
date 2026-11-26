Frozen on-disk data from release format PRISM-1 (`v1/`). All keys in it are throwaway test keys, including
the passphrase in `make_v1.py`. `tests/test_frozen_format.py` opens it with the current code, so a change that
breaks old data fails the suite instead of surprising an operator.
