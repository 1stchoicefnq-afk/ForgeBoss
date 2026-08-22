"""ForgeBoss learns from validated engineering artefacts, not private model chain-of-thought."""
MIN_REUSE_CONFIDENCE=.85
def can_promote(validation,partial_proven=False):
    if not isinstance(validation,dict): return False
    if validation.get("introduced_regression"): return False
    if validation.get("all_required_passed"): return True
    return bool(partial_proven and validation.get("focused_target_passed"))
