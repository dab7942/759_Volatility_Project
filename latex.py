# Commented line
import os
from datetime import date

from cuckoo.common.abstracts import Report
from cuckoo.common.exceptions import CuckooReportError

#global tab = "\indent"

# To do
# Add slashes \ to override underscores _ in API names
# Add families check along with references check (Works the same way)
# Start working on cool looking process tree
# File access timeline

# Notes for making process tree
# After defining a node, add "[level distance= ...]" on next line
# Use width("text") to determine distance
# Can regrab process name for this

# Also need "text centered" in tikzpicture
# And // in the text to split it across lines

class Latex(Report):

#     new_samplename = ""

     def fix_underscores(self, broke):
          underscore = broke.find("_")
          fixed = ""
          if underscore != -1:
               splits = broke.split("_")
               for bit in splits:
                    fixed += bit
                    fixed += "\_"
               fixed = fixed[0:-2]
          else:
               fixed = broke
          return fixed


     def add_title(self, results):
          title = ""
          try:
               sample = self.fix_underscores(results['target']['file']['name'])
               title += "\\title{Latex Report for " + str(sample) + "}\n"
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
                              call2 = self.fix_underscores(call)
                              sig_notes += tab + tab + call2 + " was called "
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
          rec_notes = ""
          try:
               proc_name = self.fix_underscores(node['process_name'])
               blurb = str(node['pid']) + r"\\" + proc_name
               rec_notes += "\nchild{node[roundnode]{" + blurb + "}"
               rec_notes += "[level distance=width(\"" + blurb + "\")]"
#               proc_name = self.fix_underscores(node['process_name'])
#               blurb = str(node['pid']) + "\n" + str(proc_name)
               for kid in node['children']:
                    rec_notes += self.rec_tree(kid)
               rec_notes += "}"
          except:
               raise CuckooReportError("Rec tree issue: ", sys.exec_info()[0])
          finally:
               return rec_notes
          

     def tree(self, results):
          tree_notes = ""
          try:
               tree_notes += "\\newpage"
               tree_notes += "\section{Process Tree}\n"
               tree_notes += "\label{Process Tree}\n"
               proc_tree = results['behavior']['processtree']
               for node in proc_tree:
                    tree_notes += "\\begin{tikzpicture}"
                    style = "{circle,draw=black,fill=white,minimum size=4mm}"
                    node_def = "roundnode/.style="
                    node_def += style
                    proc_name = self.fix_underscores(node['process_name'])
                    blurb = str(node['pid']) + r"\\" + proc_name
                    tree_notes += "[" + node_def + ", align=center]\n"
                    tree_notes += "\\node[roundnode]{" + blurb + "}\n"
                    tree_notes += "[level distance=width(\"" + blurb + "\")]"
                    for kid in node['children']:
                         tree_notes += self.rec_tree(kid)
                    tree_notes += ";\n"
                    tree_notes += "\end{tikzpicture}\n"
          except:
               raise CuckooReportError("Proc tree issue: ", sys.exec_info()[0])
          finally:
               return tree_notes

     def pe_sec(self, results):
          pe_notes = ""
          try:
               pe_notes += "\section{PE}\n"
               pe_notes += "\label{PE}\n"
               pe_notes += "\\begin{tikzpicture}]\n"
               total_size = 0.0
               base_shape = "\\filldraw[fill=red!{:.2f}!green, draw=black]"
               base_shape += " (0,{:.2f}) rectangle (11,{:.2f});\n"
               base_text = "\\node[anchor=west] at (1,{:.2f}) {};"
               secs = results['static']['pe_sections']
               for sec in secs:
                    size = int(sec['size_of_data'], 16)
                    total_size += float(size)
               top = 19.00
               deficit = 0
               num_sec = len(secs)
               count = 1
               for sec in secs:
                    size = int(sec['size_of_data'], 16)
                    size = float(size)
                    scale = size/total_size*19.0
                    height = 0
                    if scale < 1.00:
                         deficit += (1.00 - scale)
                         height = 1.00
                    elif scale > deficit + 2.00:
                         height = scale - deficit
                         deficit = 0.00
                    else:
                         height = scale
                    shade = float(100*count/num_sec)
                    pe_notes += base_shape.format(shade, top, top-height)
                    count += 1
                    core_text = "{" + sec['name'] + "}"
                    pe_notes += base_text.format(top-0.5, core_text) + "\n"
                    top -= height
               pe_notes += "\end{tikzpicture}"
          except:
               raise CuckooReportError("Other sig issue: ", sys.exec_info()[0])
          finally:
               return pe_notes

     # This does things
     # Attempt to do a thing
     def run(self, results):
          try:
               whole_doc = ""
               whole_doc += "\documentclass{report}\n"
               whole_doc += "\usepackage{tikz}\n"
               whole_doc += "\usepackage[a4paper, margin=1in]{geometry}\n"
               whole_doc += self.add_title(results)
               sample = self.fix_underscores(results['target']['file']['name'])
               whole_doc += "\\begin{document}\n"
               whole_doc += "\maketitle\n"
               whole_doc += "\section{Introduction}\n"
               whole_doc += "\label{Introduction}\n"
               whole_doc += "This report contains a summary of various "
               whole_doc += "activities and artifacts documented by the "
               whole_doc += "cuckoo sandbox report. This report came from "
               whole_doc += " executing a file called "
               whole_doc += str(sample) + " on a "
               whole_doc += results['info']['machine']['manager'] + " VM. "
               whole_doc += "It was given a score of "
               whole_doc += str(results['info']['score']) + ". "
               whole_doc += "The sections are: "
               whole_doc += "signatures, process tree .\n"
#               whole_doc += "There will be something here eventually\n"
               whole_doc += self.sig_analysis(results)
               whole_doc += self.tree(results)
               whole_doc += self.pe_sec(results)
# This is the very last thing to add
               whole_doc += "\end{document}"
               alt_file_path = os.path.join(self.reports_path, "latex.txt")
               with open(alt_file_path, "w") as test_report:
                    test_report.write(whole_doc)
                    test_report.close()
          except (TypeError, IOError) as e:
               raise CuckooReportError("Didn't generate duncan report: %s" % e)     
