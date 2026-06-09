clean_ev = str(f.evidence).replace("Primitive string instruction match: ", "").strip("'\" ")
f.tracked_evidence = {clean_ev}
