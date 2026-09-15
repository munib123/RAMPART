"""Joern / Code Property Graph phase: the SAST-blind logic-bug locator.

    from app.services.joern import scan as joern_scan   # scan(), enabled(), available(), warm()
    from app.services.joern import runtime              # locate(), probe(), install()

The phase is additive and never raises; see scan.py for the contract with the pipeline.
Submodules are imported explicitly (no eager re-exports) so `python -m ...runtime` stays clean.
"""
