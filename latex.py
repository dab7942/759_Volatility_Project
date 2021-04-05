# Commented line
import os
from datetime import date

from cuckoo.common.abstracts import Report
from cuckoo.common.exceptions import CuckooReportError

#global tab = "\indent"

class Latex(Report):

     def add_title(self, results):
          title = ""
          try:
               samplename = results['target']['file']['name']
               underscore = samplename.find("_")
               new_samplename = ""
               if underscore != -1:
                    splits = samplename.split("_")
                    for bit in splits:
                         new_samplename += bit
                         new_samplename += "\_"
                    new_samplename = new_samplename[0:-2]
               else:
                    new_samplename = samplename
               title += "\\title{Latex Report for " + new_samplename + "}\n"
               title += "\\author{Cuckoo Sandbox}\n"
               today = date.today().strftime("%B %d, %Y")
               title += "\date{" + today + "}\n"
          except (TypeError, IOError) as e:
               raise CuckooReportError("Error making title: %s" % e)
          finally:
               return title

     def sig_analysis(self, results):
          tab = "\indent "
          sig_notes = ""
          try:
#               sig_notes = ""
               sig_notes += "\section{Signatures}\n"
               sig_notes += "\label{Signatures}\n"
               for sig in results['signatures']:
                    sig_notes += "\\noindent "
                    sig_notes += "Description: " + sig['description'] + "\n\n"
                    calls = {}
                    refs = ""
                    for mark in sig['marks']:
                         if mark['type'] == "call":
                              api = mark['call']['api']
                              calls[api] = calls.get(api, 0) + 1
                    for ref in sig['references']:
                         refs += tab + tab + ref + "\n\n"
                    if calls != {}:
                         sig_notes += tab + "Relevant API Calls\n\n"
                         for call, count in calls.items():
                              sig_notes += tab + tab + call + " was called "
                              sig_notes += str(count) + " times\n\n"
                    if refs != "":
                         sig_notes += tab + "For further info\n\n"
                         sig_notes += refs
# Leaving this part out until I learn what families actually looks like
#               if len(sig['families']) > 0:
#                    sig_notes += "\t Families\n"
#                    for fam in sig['families']:
          except (TypeError, IOError) as e:
               raise CuckooReportError("Issue with sig analysis: %s" % e)
          except:
               raise CuckooReportError("Other sig issue: ", sys.exec_info()[0])
          finally:
               return sig_notes

     def rec_tree(self, node):
          notes_list = []
          try:
               rec_notes = ""
#               notes_list = []
               pid = node['pid']
               kids = []
               rec_notes += "Process " + str(pid) + " had kids"
               for kid in node['children']:
                    rec_notes += " " + str(kid['pid'])
                    kid_info = self.rec_tree(kid)
                    notes_list += kid_info
               rec_notes += "\n\n"
               notes_list.append(rec_notes)
          except:
               raise CuckooReportError("Rec tree issue: ", sys.exec_info()[0])
          finally:
               return notes_list
          

     def tree(self, results):
          tree_notes = ""
          try:
#               tree_notes = ""
               tree_list = []
               tree_notes += "\section{Process Tree}\n"
               tree_notes += "\label{Process Tree}\n"
               proc_tree = results['behavior']['processtree']
               for node in proc_tree:
#                    tree_list.append(self.rec_tree(node))
#               for item in tree_list:
#                    tree_notes += item
                    pid = node['pid']
#                    kids = []
                    tree_notes += "Process " + str(pid) + " had kids"
                    for kid in node['children']:
                         tree_notes += " " + str(kid['pid'])
                    tree_notes += "\n\n"
          except:
               raise CuckooReportError("Other sig issue: ", sys.exec_info()[0])
          finally:
               return tree_notes

     # This does things
     # Attempt to do a thing
     def run(self, results):
          try:
               whole_document = ""
               whole_document += "\documentclass{report}\n"
               whole_document += self.add_title(results)
               whole_document += "\\begin{document}\n"
               whole_document += "\maketitle\n"
               whole_document += "\section{Introduction}\n"
               whole_document += "\label{Introduction}\n"
               whole_document += "There will be something here eventually\n"
               whole_document += self.sig_analysis(results)
               whole_document += self.tree(results)
# This is the very last thing to add
               whole_document += "\end{document}"
               alt_file_path = os.path.join(self.reports_path, "latex.txt")
               with open(alt_file_path, "w") as test_report:
                    test_report.write(whole_document)
                    test_report.close()
          except (TypeError, IOError) as e:
               raise CuckooReportError("Didn't generate duncan report: %s" % e)     
