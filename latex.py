# Commented line
import os
from datetime import date

from cuckoo.common.abstracts import Report
from cuckoo.common.exceptions import CuckooReportError

#global tab = "\indent"

sample = ""

# To do
# File access timeline
  # Found the right place to find this info. Start on code tomorrow.
# Maybe improve process tree somehow?
# Gotta find something else

# OK Regkey stuff is working close enough to good for now
# Wednesday, improve it to check for all possible activity keys
# And then do the same thing for file activity

# Notes from Wednesday
# Regkey seems to be working properly
# Transfer code into Files at next opportunity

# Notes from Thursday
# Found the problem with filesystem
# file_copied is a list of both the og file and the copied one
# Fixed by concattenating them into one
# But will need to fix how I check for them in the backwards and forwards check

# THESE THINGS ARE DONE
# Improve API call graphs by fixing alignment & adding Title/Header
  # This should be solved
# Added graph for overall stats
# Consider adding additional function for graph gereration to offload code
  # Actually this isn't possible since I need to build the overall stats

class Latex(Report):

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

     def fix_slash(self, broke):
          slash = broke.find("\\")
          fixed = ""
          if slash != -1:
               splits = broke.split("\\")
               for bit in splits:
                    fixed += bit
                    fixed += " \\textbackslash "
          else:
               fixed = broke
          return fixed

     def fix_percent(self, broke):
          percent = broke.find("%")
          fixed = ""
          if percent != -1:
               splits = broke.split("%")
               for bit in splits:
                    fixed += bit
                    fixed += "\%"
          else:
               fixed = broke
          return fixed

     def add_title(self, results):
          title = ""
          try:
               global sample
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
          apis = []
          try:
               sig_notes += "\section{Signatures}\n"
               sig_notes += "\label{Signatures}\n"
               for sig in results['signatures']:
                    sig_notes += "\\noindent "
                    sig_notes += "Description: " + sig['description'] + "\n\n"
                    calls = {}
                    refs = ""
                    fams = ""
                    for mark in sig['marks']:
                         if mark['type'] == "call":
                              api = mark['call']['api']
                              calls[api] = calls.get(api, 0) + 1
                              apis.append(api)
                    for ref in sig['references']:
                         refs += tab + tab + ref + "\n\n"
                    for fam in sig['families']:
                         fams += tab + tab + fam + "\n\n"
                    if calls != {}:
                         sig_notes += tab + "Relevant API Calls\n\n"
                         for call, count in calls.items():
                              call2 = self.fix_underscores(call)
                              sig_notes += tab + tab + call2 + " was called "
                              sig_notes += str(count) + " times\n\n"
                    if refs != "":
                         sig_notes += tab + "For further info\n\n"
                         sig_notes += refs
                    if fams != "":
                         sig_notes += tab + "Families with this signature\n\n"
                         sig_notes += fams
          except (TypeError, IOError) as e:
               raise CuckooReportError("Issue with sig analysis: %s" % e)
          except:
               raise CuckooReportError("Other sig issue: ", sys.exec_info()[0])
          finally:
               return (sig_notes, apis)

     def rec_tree(self, node):
          rec_notes = ""
          try:
               proc_name = self.fix_underscores(node['process_name'])
               blurb = str(node['pid']) + r"\\" + proc_name
               rec_notes += "\nchild{node[roundnode]{" + blurb + "}"
               rec_notes += "[level distance=width(\"" + blurb + "\")]"
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
                    l1 = "level 1/.style={sibling distance = 30mm},"
                    grn = "{circle,draw=black,fill=green!50,minimum size=4mm},"
                    red = "{circle,draw=black,fill=red!50,minimum size=4mm},"
                    ng = "{circle,draw=black,fill=orange!50,minimum size=4mm},"
                    proc_name = self.fix_underscores(node['process_name'])
                    if(proc_name[-4:] == ".exe"):
                         proc_name = proc_name[0:-4]
                    global sample
                    node_def = ""
                    if(proc_name == sample):
                         node_def = "roundnode/.style=" + red
                    elif(proc_name == "lsass"):
                         node_def = "roundnode/.style=" + grn
                    else:
                         node_def = "roundnode/.style=" + ng
                    blurb = str(node['pid']) + r"\\" + proc_name
                    tree_notes += "[" + l1 + node_def + "align=center]\n"
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
                    core_text = "{" + self.fix_slash(sec['name']) + "}"
                    pe_notes += base_text.format(top-0.5, core_text) + "\n"
                    top -= height
               pe_notes += "\end{tikzpicture}"
          except:
               raise CuckooReportError("Other sig issue: ", sys.exec_info()[0])
          finally:
               return pe_notes

     def apicalls(self, results, badapis):
          call_notes = ""
          try:
               call_notes += "\section{API Calls}\n"
               call_notes += "\label{API Calls}\n"
               stats = results['behavior']['apistats']
               totals = {}
               for proc in stats:
                    graph = "\\begin{tikzpicture}\n\\begin{axis}\n"
                    graph += "[ybar, enlargelimits=0.15, ylabel={Count}, "
                    graph += "title={Most common calls for " + str(proc) + "}"
                    graph += ", nodes near coords, "
                    graph += "nodes near coords align={vertical}, "
                    graph += "xticklabel style={rotate=-90},"
                    coords = "symbolic x coords={"
                    plots = "\\addplot coordinates {"
                    redplots = "\\addplot[ybar,fill=red] coordinates {"
                    calls = []
                    counts = []
                    for key in stats[proc]:
                         calls.append(key)
                         counts.append(stats[proc][key])
                         totals[key] = totals.get(key, 0) + stats[proc][key]
                    for i in range(5):
                          index = counts.index(max(counts))
                          call = calls[index]
                          coords += call + ", "
                          if call in badapis:
                               redplots += "(" + call + ", "
                               redplots += str(counts[index]) + ") "
                          else:
                               plots += "(" + call + ", "
                               plots += str(counts[index]) + ") "
                          calls = calls[:index] + calls[index+1:]
                          counts = counts[:index] + counts[index+1:]
                    coords += "}]\n"
                    plots += "};\n"
                    redplots += "};\n"
                    graph += coords + plots + redplots
                    graph += "\end{axis}\n\end{tikzpicture}\n"
                    call_notes += graph
               graph = "\\begin{tikzpicture}\n\\begin{axis}\n"
               graph += "[ybar, enlargelimits=0.15, ylabel={Count}, "
               graph += "title={Most common calls overall}"
               graph += ", nodes near coords, "
               graph += "nodes near coords align={vertical}, "
               graph += "xticklabel style={rotate=-90},"
               coords = "symbolic x coords={"
               plots = "\\addplot coordinates {"
               redplots = "\\addplot[fill=red] coordinates {"
               calls = []
               counts = []
               for key in totals:
                    calls.append(key)
                    counts.append(totals[key])
               for i in range(5):
                     index = counts.index(max(counts))
                     coords += calls[index] + ", "
                     if calls[index] in badapis:
                          redplots += "(" + calls[index] + ", "
                          redplots += str(counts[index]) + ") "
                     else:
                          plots += "(" + calls[index] + ", "
                          plots += str(counts[index]) + ") "
                     calls = calls[:index] + calls[index+1:]
                     counts = counts[:index] + counts[index+1:]
               coords += "}]\n"
               plots += "};\n"
               redplots += "};\n"
               graph += coords + plots + redplots
               graph += "\end{axis}\n\end{tikzpicture}\n"
               call_notes += graph
          except:
               raise CuckooReportError("API issue: ", sys.exec_info()[0])
          finally:
               return call_notes

     def fileactivity(self, results):
          file_notes = ""
          try:
               file_notes += ""
               file_notes += "\section{File System Activity}\n"
               file_notes += "\label{File System Activity}\n"
               summary = results['behavior']['summary']
               file_keys = []
               used_keys = []
               for key in summary:
                    if "file_" in key:
                         file_keys.append(key)
               count = len(file_keys)
               used = len(used_keys)
               if count == 0:
                    file_notes += "There was no filesystem activity.\n"
                    return file_notes
               file_notes += "\\begin{center}\n"
               file_notes += "\\begin{longtable}"
               w = str(1-count/10.0)
               file_notes += "{||p{" + w + "\linewidth}" + " c"*count + "||}\n"
               file_notes += "\hline\n"
               file_notes += "File"
               for key in file_keys:
                    file_notes += " & " + str(key[5:])
               file_notes += " \\\\ \n \hline\hline\n"
#               reg_notes += "Filler " + "& full"*count + "\\\\ \n"
#               reg_notes += "\hline\n"
               while len(file_keys) > 0:
                    count = len(file_keys)
                    used = len(used_keys)
                    current = file_keys[0]
                    file_keys = file_keys[1:]
                    for fle in summary[current]:
                         if current == "file_copied":
                              fle = fle[0] + " aka " + fle[1]
                         seen = False
                         for key in used_keys:
                              if fle in summary[key]:
                                   seen = True
                         if not seen:
                              fle2 = self.fix_underscores(self.fix_slash(fle))
                              file_notes += fle2 + " & no"*used + " & yes"
                              for key in file_keys:
                                   if fle in summary[key]:
                                        file_notes += " & yes"
                                   else:
                                        file_notes += " & no"
                              file_notes += "\\\\ \n \hline\n"
                    used_keys.append(current)
               file_notes += "\end{longtable}\n"
               file_notes += "\end{center}\n"

#               file_notes += "\\begin{center}\n"
#               file_notes += "\\begin{longtable}{||p{0.3\linewidth} c c c c||}\n"
#               file_notes += "\hline\n"
#               file_notes += "File & Exists & Opened & Read & Written \\\\ \n"
#               file_notes += "\hline\hline\n"
#               file_notes += "Filler & filler & fiiier & fillier & full\\\\ \n"
#               file_notes += "\hline\n"
##               summary = results['behavior']['summary']
#               if summary.has_key("file_exists"):
#                    for afile in summary["file_exists"]:
#                         afile2 = self.fix_slash(afile)
#                         afile2 = self.fix_underscores(afile2)
#                         file_notes += afile2 + " & yes"
#                         for key in ["file_opened", "file_read", "file_written"]:
#                              if summary.has_key(key) and afile in summary[key]:
#                                   file_notes += " & yes"
#                              else:
#                                   file_notes += " & no"
#                         file_notes += " \\\\ \n \hline\n"
#               file_notes += "\end{longtable}\n"
#               file_notes += "\end{center}\n"
          except:
               raise CuckooReportError("Files issue: ", sys.exec_info()[0])
          finally:
               return file_notes

     def regactivity(self, results):
          reg_notes = ""
          try:
               reg_notes += ""
               reg_notes += "\section{Registry Activity}\n"
               reg_notes += "\label{Registry Activity}\n"
               summary = results['behavior']['summary']
               reg_keys = []
               used_keys = []
               for key in summary:
                    if "regkey_" in key:
                         reg_keys.append(key)
               count = len(reg_keys)
               used = len(used_keys)
               if count == 0:
                    reg_notes += "There was no registry activity.\n"
                    return reg_notes
               reg_notes += "\\begin{center}\n"
               reg_notes += "\\begin{longtable}"
               w = str(1-count/10.0)
               reg_notes += "{||p{"+ w + "\linewidth}" + " c"*count + "||}\n"
               reg_notes += "\hline\n"
               reg_notes += "Registry "
               for key in reg_keys:
                    reg_notes += "& " + str(key[7:]) + " "
               reg_notes += "\\\\ \n \hline\hline\n"
#               reg_notes += "Filler " + "& full"*count + "\\\\ \n"
#               reg_notes += "\hline\n"
               while len(reg_keys) > 0:
                    count = len(reg_keys)
                    used = len(used_keys)
                    current = reg_keys[0]
                    reg_keys = reg_keys[1:]
                    for reg in summary[current]:
                         seen = False
                         for key in used_keys:
                              if reg in summary[key]:
                                   seen = True
                         if not seen:
                              reg2 = self.fix_slash(reg)
                              reg2 = self.fix_underscores(reg2)
                              reg2 = self.fix_percent(reg2)
                              reg_notes += reg2 + " & no"*used + " & yes"
                              for key in reg_keys:
                                   if reg in summary[key]:
                                        reg_notes += " & yes"
                                   else:
                                        reg_notes += " & no"
                         reg_notes += "\\\\ \n \hline\n"
                    used_keys.append(current)
               reg_notes += "\end{longtable}\n"
               reg_notes += "\end{center}\n"
          except:
               raise CuckooReportError("Registry issue: ", sys.exec_info()[0])
          finally:
               return reg_notes

     # This does things
     # Attempt to do a thing
     def run(self, results):
          try:
               global sample
               sample = self.fix_underscores(results['target']['file']['name'])
               whole_doc = ""
               whole_doc += "\documentclass{report}\n"
               whole_doc += "\usepackage{tikz}\n"
               whole_doc += "\usepackage[a4paper, margin=1in]{geometry}\n"
               whole_doc += "\usepackage{pgfplots}\n"
               whole_doc += "\usepackage{longtable}\n"
               whole_doc += self.add_title(results)
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
               (sigs, apis) = self.sig_analysis(results)
               whole_doc += sigs
#               whole_doc += self.sig_analysis(results)
               whole_doc += self.tree(results)
               whole_doc += self.pe_sec(results)
               whole_doc += self.apicalls(results, apis)
               whole_doc += self.fileactivity(results)
               whole_doc += self.regactivity(results)
# This is the very last thing to add
               whole_doc += "\end{document}"
               alt_file_path = os.path.join(self.reports_path, "latex.txt")
               with open(alt_file_path, "w") as test_report:
                    test_report.write(whole_doc)
                    test_report.close()
          except (TypeError, IOError) as e:
               raise CuckooReportError("Didn't generate duncan report: %s" % e)     
