import secrets,time
def new_operation_id(prefix="FB"):return f"{prefix}-{time.strftime('%Y%m%d-%H%M%S',time.gmtime())}-{secrets.token_hex(8)}"
def verify_result_id(r,e):
 if r.get("operation_id")!=e:raise ValueError("operation_id mismatch")
 return r
