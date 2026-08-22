from pathlib import Path
import re
ROOT=Path(__file__).resolve().parents[2]
rr=(ROOT/"SiteBoss-Repair-Rat.ps1").read_text(encoding="utf-8-sig")

identifier=re.compile(r'^[A-Za-z_$][A-Za-z0-9_$]{3,79}$')
cases={
 "identity":True,
 "withSerializableRetry":True,
 "issue":True,
 "PostgresBusinessInvitationService.issue: wrap the SERIALIZABLE withTenant/tenant":False,
 "src/file.js: function":False,
 "withTransaction()":False,
 "a":False,
}
for value,expected in cases.items():
    got=bool(identifier.fullmatch(value))
    assert got==expected,(value,got,expected)

assert "anchor_locator is PRIMARY" in rr
assert "located '$Hint' occurrence is not a definition" in rr
assert "method declarations" in rr
assert "prose hints are forbidden" in rr
print("FORGEBOSS v2.2.1 MODEL CONTRACT MATRIX PASS=4 FAIL=0")
