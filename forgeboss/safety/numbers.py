import math
def finite_number(v,name="value",lo=None,hi=None):
 v=float(v)
 if not math.isfinite(v):raise ValueError(f"{name} must be a finite number")
 if lo is not None and v<lo:raise ValueError(f"{name} below minimum")
 if hi is not None and v>hi:raise ValueError(f"{name} above maximum")
 return v
