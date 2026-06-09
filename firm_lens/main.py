def process_finding_evidence(f):
    """Process finding evidence to extract actual matched artifacts."""
    clean_ev = str(f.evidence).replace("Primitive string instruction match: ", "").strip("'\" ")
    f.tracked_evidence = {clean_ev}
