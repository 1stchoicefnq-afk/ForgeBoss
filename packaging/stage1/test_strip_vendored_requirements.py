from __future__ import annotations
import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from strip_vendored_requirements import strip_requirement

class StripVendoredRequirementTests(unittest.TestCase):
    def test_removes_multiline_requirement_and_via_comment(self):
        raw="a==1 \\\n  --hash=x\nproxy-tools==0.1.0 \\\n  --hash=y\n    # via pywebview\nb==2 \\\n  --hash=z\n"
        out=strip_requirement(raw,"proxy-tools")
        self.assertIn("a==1",out);self.assertIn("b==2",out);self.assertNotIn("proxy-tools",out);self.assertNotIn("via pywebview",out)
    def test_missing_requirement_fails(self):
        with self.assertRaises(RuntimeError):strip_requirement("a==1\n","proxy-tools")
if __name__=="__main__":unittest.main()
