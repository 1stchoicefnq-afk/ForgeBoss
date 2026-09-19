from __future__ import annotations
import tempfile, unittest, zipfile
from pathlib import Path
from forgeboss.control.project_intake import FORGEBOSS_MARKERS,detect_project_source

class ProjectIntakeTests(unittest.TestCase):
    def make_tree(self,root):
        for rel in FORGEBOSS_MARKERS:
            p=root/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_text("x",encoding="utf-8")

    def test_folder_is_recognised(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"ForgeBoss";root.mkdir();self.make_tree(root)
            x=detect_project_source(str(root))
            self.assertEqual(x["project_id"],"forgeboss");self.assertEqual(x["source_kind"],"folder")
            self.assertEqual(Path(x["source_path"]),root.resolve())

    def test_file_inside_folder_resolves_root(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"ForgeBoss";root.mkdir();self.make_tree(root)
            x=detect_project_source(str(root/"dashboard"/"pro_shell.py"))
            self.assertEqual(Path(x["source_path"]),root.resolve())

    def test_zip_with_top_folder_is_recognised(self):
        with tempfile.TemporaryDirectory() as td:
            zpath=Path(td)/"ForgeBoss.zip"
            with zipfile.ZipFile(zpath,"w") as z:
                for rel in FORGEBOSS_MARKERS:z.writestr("ForgeBoss/"+rel,"x")
            x=detect_project_source(str(zpath))
            self.assertEqual(x["source_kind"],"zip");self.assertEqual(x["zip_prefix"],"ForgeBoss/")

    def test_incomplete_tree_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);(root/"dashboard").mkdir();(root/"dashboard"/"pro_shell.py").write_text("x")
            with self.assertRaises(ValueError):detect_project_source(str(root))

    def test_relative_path_rejected(self):
        with self.assertRaises(ValueError):detect_project_source("ForgeBoss.zip")

if __name__=="__main__":unittest.main()
