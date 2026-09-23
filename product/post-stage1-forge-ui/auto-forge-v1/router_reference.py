def normalize_ai_mode(mode):
    m=str(mode or "cost-optimized").strip().lower()
    aliases={
        "auto":"auto","smart":"auto","smart-auto":"auto","auto-forge":"auto",
        "cost-optimized":"auto",
        "repair-rat":"repair-rat","repair_rat":"repair-rat",
        "cheap":"low-heat","low":"low-heat","low-heat":"low-heat",
        "balanced":"balanced","working-heat":"balanced",
        "strong":"strong","high-heat":"strong",
        "full":"full","full-forge":"full","max":"full","max-power":"full",
    }
    if m not in aliases: raise ValueError(f"Unknown AI mode: {mode}")
    return aliases[m]

def is_auto_mode(mode):
    return normalize_ai_mode(mode)=="auto"

def choose_openai_lane(mode,cycle,same_signature_count,auto_escalation_level=0):
    mode=normalize_ai_mode(mode)
    try: level=max(0,min(int(auto_escalation_level or 0),2))
    except Exception: level=0
    if mode=="auto":
        lanes=(
            {"model":"gpt-5.6-luna","reasoning":"low","max_output":3000,"lane":"LOW_HEAT"},
            {"model":"gpt-5.6-terra","reasoning":"medium","max_output":4000,"lane":"WORKING_HEAT"},
            {"model":"gpt-5.6-sol","reasoning":"medium","max_output":5000,"lane":"HIGH_HEAT"},
        )
        out=dict(lanes[level])
        out.update({"requested_mode":"auto","escalation_level":level,
                    "route_reason":"cheap-first Repair Rat route" if level==0 else "repeated bounded failure evidence justified more heat"})
        return out
    if mode in ("repair-rat","low-heat"):
        return {"requested_mode":mode,"model":"gpt-5.6-luna","reasoning":"low","max_output":3000,
                "lane":"REPAIR_RAT" if mode=="repair-rat" else "LOW_HEAT","escalation_level":0,
                "route_reason":"fixed low-cost lane; automatic paid escalation disabled"}
    if mode=="balanced":
        return {"requested_mode":mode,"model":"gpt-5.6-terra","reasoning":"medium","max_output":4000,
                "lane":"WORKING_HEAT","escalation_level":1,"route_reason":"owner selected balanced lane"}
    if mode=="strong":
        return {"requested_mode":mode,"model":"gpt-5.6-sol","reasoning":"medium","max_output":5000,
                "lane":"HIGH_HEAT","escalation_level":2,"route_reason":"owner selected strong lane"}
    if mode=="full":
        return {"requested_mode":mode,"model":"gpt-5.6-sol","reasoning":"high","max_output":6500,
                "lane":"FULL_FORGE","escalation_level":2,"route_reason":"owner selected full forge"}
    raise ValueError(f"Unknown AI mode: {mode}")

def auto_forge_escalation_decision(mode,same_signature_count,auto_escalation_level):
    if not is_auto_mode(mode):
        return {"action":"hold","level":int(auto_escalation_level or 0),"reason":"fixed owner-selected lane"}
    count=max(0,int(same_signature_count or 0))
    level=max(0,min(int(auto_escalation_level or 0),2))
    if count>=1 and level<1:
        return {"action":"escalate","level":1,"reason":"same bounded failure signature repeated after focused retry"}
    if count>=2 and level<2:
        return {"action":"escalate","level":2,"reason":"same bounded failure signature survived Working Heat"}
    if count>=3 and level>=2:
        return {"action":"stop","level":2,"reason":"same bounded failure persisted at maximum approved heat"}
    return {"action":"hold","level":level,"reason":"no escalation evidence"}
