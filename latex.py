# Commented line
import os

from cuckoo.common.abstracts import Report
from cuckoo.common.exceptions import CuckooReportError

class Latex(Report):
     # This does things
     # Attempt to do a thing
     def run(self, results):
          try:
               alt_file_path = os.path.join(self.reports_path, "latex.txt")
               with open(alt_file_path, "w") as test_report:
                    test_report.write("I AM CREATING A FILE!!!")
                    test_report.close()
          except (TypeError, IOError) as e:
               raise CuckooReportError("Didn't generate duncan report: %s" % e)     
