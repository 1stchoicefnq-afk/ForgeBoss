from pathlib import Path
import tempfile
from forgeboss.control.projects import load_profile,list_profiles,validate_profile
from forgeboss.control.scheduler import WorkItem,smart_parallel_batches
from forgeboss.learning.store import LearningStore
ids={p["id"] for p in list_profiles()}
assert {"siteboss","siteboss-connect","scroll-animation"} <= ids
assert validate_profile(load_profile("siteboss"))
items=[WorkItem("a","postgres",{"src/a.js"},{"src/a.js"},.02,1),WorkItem("b","frontend",{"src/b.js"},{"src/b.js"},.02,2),WorkItem("c","same",{"src/a.js"},{"src/a.js"},.02,3),WorkItem("d","other",{"src/d.js"},{"src/d.js"},.02,4)]
b=smart_parallel_batches(items,4)
assert len(b)>=2 and {x.task_id for x in b[0]}=={"a","b","d"}
with tempfile.TemporaryDirectory() as td:
    st=LearningStore(Path(td)/"learning.db")
    lid=st.record_verified_lesson("siteboss","postgres-40001","retry whole transaction",{"kind":"patch-pattern"},{"codes":["40001"]},{"all_required_passed":True})
    assert st.find_reusable("siteboss","postgres-40001")[0]["lesson_id"]==lid
    st.record_worker_result("siteboss","repair-rat","postgres-40001",True,.02,1200)
    assert st.best_workers("siteboss","postgres-40001")[0]["worker_id"]=="repair-rat"
print("FORGEBOSS v2.1 PROJECT/LEARNING SELFTEST PASS")
