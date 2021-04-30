# Commented line
import os
from datetime import date

from cuckoo.common.abstracts import Report
from cuckoo.common.exceptions import CuckooReportError

sample = ""
sample_pure = ""

class Latex(Report):

# Function for putting slashes in a format Latex can use
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

# Function to put various symbols into appropriate format for Latex
     def fix_all(self, broke):
          fixed = ""
          for symbol in ["_", "%", "$"]:
               fixed = ""
               present = broke.find(symbol)
               if present != -1:
                    splits = broke.split(symbol)
                    for bit in splits:
                         fixed += bit
                         if bit != splits[-1]:
                              fixed += "\\" + symbol
               else:
                    fixed = broke + ""
               broke = fixed + ""
          return fixed

# Creates a title page for the report
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

# Extract the signature descriptions from the JSON
# For certain sig types, extract additional info
     def sig_analysis(self, results):
          tab = "\indent "
          sig_notes = ""
          apis = []
          try:
               sig_notes += "\section{Signatures}\n"
               sig_notes += "\label{Signatures}\n"
               sig_notes += "This section outlines information about the"
               sig_notes += " different signatures observed during sample"
               sig_notes += " execution. These signatures are created by the"
               sig_notes += " Cuckoo community, so make note of all of them."
               sig_notes += "The description for each signature is given,"
               sig_notes += " along with relevant 'marks', which provide more"
               sig_notes += " details about what activity occurred.\n \\\\"
               for sig in results['signatures']:
                    sig_notes += "\\noindent "
                    sig_notes += "Description: " + sig['description'] + "\n\n"
                    calls = {}
                    wmi = ""
                    dns = ""
                    dead = ""
                    refs = ""
                    fams = ""
                    for mark in sig['marks']:
                         if mark['type'] == "call":
                              api = mark['call']['api']
                              calls[api] = calls.get(api, 0) + 1
                              apis.append(api)
                         if mark['type'] == "ioc":
                              if mark['category'] == 'wmi':
                                   wmi += tab + tab + mark['ioc'] + "\n\n"
                              elif mark['category'] == "dead_host":
                                   dead += tab + tab + mark['ioc'] + "\n\n"
                         if mark['type'] == "generic" & mark.has_key("host"):
                              dns += tab + tab + mark['host'] + "\n\n"
                    for ref in sig['references']:
                         refs += tab + tab + ref + "\n\n"
                    for fam in sig['families']:
                         fams += tab + tab + fam + "\n\n"
                    if calls != {}:
                         sig_notes += tab + "Relevant API Calls\n\n"
                         for call, count in calls.items():
                              call2 = self.fix_all(call)
                              sig_notes += tab + tab + call2 + " was called "
                              sig_notes += str(count) + " times\n\n"
                    if wmi != "":
                         sig_notes += tab + "WMI Queries made\n\n"
                         sig_notes += wmi
                    if dns != "":
                         sig_notes += tab + "DNS Queries made\n\n"
                         sig_notes += dns
                    if dead != "":
                         sig_notes += tab + "Dead Connections made\n\n"
                         sig_notes += dead
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

# Recursive helper function for process tree generation
     def rec_tree(self, node, red):
          rec_notes = ""
          mal_procs = []
          try:
               if red:
                    mal_procs.append(node['pid'])
               proc_name = self.fix_all(node['process_name'])
               blurb = str(node['pid']) + r"\\" + proc_name
               rec_notes += "\nchild{node[roundnode]{" + blurb + "}"
               rec_notes += "[level distance=width(\"" + blurb + "\")]"
               sub_notes = ""
               sub_procs = []
               for kid in node['children']:
                    (sub_notes, sub_procs) = self.rec_tree(kid, red)
               rec_notes += sub_notes
               mal_procs += sub_procs
               rec_notes += "}"
          except:
               raise CuckooReportError("Rec tree issue: ", sys.exec_info()[0])
          finally:
               return (rec_notes, mal_procs)

# Main function for process tree generation
     def tree(self, results):
          tree_notes = ""
          mal_procs = []
          try:
               tree_notes += "\\newpage"
               tree_notes += "\section{Process Tree}\n"
               tree_notes += "\label{Process Tree}\n"
               tree_notes += "This is a set of processes observed during"
               tree_notes += " sample execution. The tree in red is the one"
               tree_notes += " containing the sample. The tree in green is "
               tree_notes += " lsass, which is responsible for starting the"
               tree_notes += " sample execution. All other trees are in"
               tree_notes += " orange. At some point additional functionality"
               tree_notes += " may be added to identify definitively"
               tree_notes += " malicious or benign trees, and color them"
               tree_notes += " appropriately.\n\n"
               proc_tree = results['behavior']['processtree']
               for node in proc_tree:
                    tree_notes += "\\begin{tikzpicture}"
                    l1 = "level 1/.style={sibling distance = 30mm},"
                    grn = "{circle,draw=black,fill=green!50,minimum size=4mm},"
                    red = "{circle,draw=black,fill=red!50,minimum size=4mm},"
                    ng = "{circle,draw=black,fill=orange!50,minimum size=4mm},"
                    proc_name_pure = node['process_name']
                    proc_name = self.fix_all(proc_name_pure)
                    if(proc_name[-4:] == ".exe"):
                         proc_name = proc_name[0:-4]
                    if(proc_name_pure[-4:] == ".exe"):
                         proc_name_pure = proc_name_pure[0:-4]
                    proc_name = self.fix_all(node['process_name'])
                    global sample
                    global sample_pure
                    node_def = ""
                    is_sample = False
                    if(proc_name_pure == sample_pure):
                         node_def = "roundnode/.style=" + red
                         mal_procs.append(node['pid'])
                         is_sample = True
                    elif(proc_name_pure == "lsass"):
                         node_def = "roundnode/.style=" + grn
                    else:
                         node_def = "roundnode/.style=" + ng
                    blurb = str(node['pid']) + r"\\" + proc_name
                    tree_notes += "[" + l1 + node_def + "align=center]\n"
                    tree_notes += "\\node[roundnode]{" + blurb + "}\n"
                    tree_notes += "[level distance=width(\"" + blurb + "\")]"
                    sub_notes = ""
                    sub_procs = []
                    for kid in node['children']:
                         (sub_notes, sub_procs) = self.rec_tree(kid, is_sample)
                    tree_notes += sub_notes
                    mal_procs += sub_procs
                    tree_notes += ";\n"
                    tree_notes += "\end{tikzpicture}\n"
          except:
               raise CuckooReportError("Proc tree issue: ", sys.exec_info()[0])
          finally:
               return (tree_notes, mal_procs)

# Function for creating scale model of PE file
     def pe_sec(self, results):
          pe_notes = ""
          try:
               pe_notes += "\section{PE}\n"
               pe_notes += "\label{PE}\n"
               pe_notes += "This section is a display of the sections of"
               pe_notes += " the submitted sample. Each section is roughly"
               pe_notes += " proportional in size to how large it is in the"
               pe_notes += " file. This section is only for purposes of"
               pe_notes += " understanding the file sections and layout.\n\n"
               pe_notes += "\\begin{tikzpicture}\n"
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
                    core_text = "{" + self.fix_all(sec['name']) + "}"
                    pe_notes += base_text.format(top-0.5, core_text) + "\n"
                    top -= height
               pe_notes += "\end{tikzpicture}\n"
          except:
               raise CuckooReportError("Other sig issue: ", sys.exec_info()[0])
          finally:
               return pe_notes

# Function for creating graphs of API call use by different processes
     def apicalls(self, results, badapis):
          call_notes = ""
          try:
               call_notes += "\section{API Calls}\n"
               call_notes += "\label{API Calls}\n"
               call_notes += "This section is a series of graphs indicating"
               call_notes += " the 5 most common API calls used by each"
               call_notes += " process that was detected by cuckoo. API calls"
               call_notes += " are how malware samples do a significant amount"
               call_notes += " of their activity. These should be checked"
               call_notes += " carefully for suspicious calls."
               call_notes += " Red columns are APIs that appeared as part of a"
               call_notes += " signature (See section 0.2). These should be"
               call_notes += " treated with extra suspicious. The last graph"
               call_notes += " is the most common API calls overall."
               call_notes += " Additional functionality to identify"
               call_notes += " potentially malicious API calls may be added"
               call_notes += " at a later date.\n\n"
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

# Determine if row for file/reg activity needs to be red
     def get_color(self, results, a_file, procs):
          color = ""
          try:
               gen = results['behavior']['generic']
               for proc in gen:
                    if proc['pid'] in procs:
                         for key in proc['summary']:
                              if a_file in proc['summary'][key]:
                                   color = "\\rowcolor{MyRed}\n"
               if "aka" in a_file:
                    spot = a_file.find(" aka ")
                    one = a_file[:spot]
                    two = a_file[spot+5:]
                    for afl in [one, two]:
                         for proc in gen:
                              if proc['pid'] in procs:
                                   for key in proc['summary']:
                                        if afl in proc['summary'][key]:
                                             color = "\\rowcolor{MyRed}\n"
          except:
               raise CuckooReportError("Coloring issue: ", sys.exec_info()[0])
          finally:
               return color

# Unused function that determines all the processes that accessed a file/reg
     def get_pids(self, results, a_file):
          pids = []
          try:
               gen = results['behavior']['generic']
               for proc in gen:
                    for key in proc['summary']:
                         if a_file in proc['summary'][key]:
                              pids.append(proc['pid'])
               if "aka" in a_file:
                    spot = a_file.find(" aka ")
                    one = a_file[:spot]
                    two = a_file[spot+5:]
                    for afl in [one, two]:
                         for proc in gen:
                              for key in proc['summary']:
                                   if afl in proc['summary'][key]:
                                        pids.append(proc['pid'])
          except:
               raise CuckooReportError("PID get issue: ", sys.exec_info()[0])
          finally:
               return pids

# Creates table of accessed files & what actions were performed on them
     def fileactivity(self, results, procs):
          file_notes = ""
          try:
               file_notes += ""
               file_notes += "\section{File System Activity}\n"
               file_notes += "\label{File System Activity}\n"
               file_notes += "\definecolor{MyRed}{rgb}{0.95,0,0}\n"
               file_notes += "This section outlines all the interactions"
               file_notes += " processes made with the filesystem. This allows"
               file_notes += " analysts to see activity with the same file"
               file_notes += " spread across multiple processes. Additionally"
               file_notes += " copied files have the activity for both their"
               file_notes += " versions combined. Entries in red were"
               file_notes += " handled by a process in the process tree"
               file_notes += " containing the executed sample. These should"
               file_notes += " be investigated further.\n\n"
               summary = results['behavior']['summary']
               file_keys = []
               used_keys = []
               double_keys = ["file_copied", "file_moved"]
               for key in double_keys:
                    if key in summary:
                         file_keys.append(key)
               for key in summary:
                    if "file_" in key and key not in double_keys:
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
               while len(file_keys) > 0:
                    count = len(file_keys)
                    used = len(used_keys)
                    current = file_keys[0]
                    file_keys = file_keys[1:]
                    for fle in summary[current]:
                         if current in double_keys:
                              fle = fle[0] + " aka " + fle[1]
                         seen = False
                         for key in used_keys:
                              if key in double_keys:
                                   masterlist = []
                                   for pair in summary[key]:
                                        masterlist.append(pair[0])
                                        masterlist.append(pair[1])
                                   if fle in masterlist:
                                        seen = True
                              else:
                                   if fle in summary[key]:
                                        seen = True
                         if not seen:
                              color = self.get_color(results, fle, procs)
                              file_notes += color
                              fle2 = self.fix_slash(fle)
                              fle2 = self.fix_all(fle2)
                              file_notes += fle2 + " & no"*used + " & yes"
                              for key in file_keys:
                                   if current in double_keys:
                                        spot = fle.find(" aka ")
                                        one = fle[:spot]
                                        two = fle[spot+5:]
                                        seen = False
                                        for afl in [one, two]:
                                             if afl in summary[key]:
                                                  seen = True
                                        if seen:
                                             file_notes += " & yes"
                                        else:
                                             file_notes += " & no"
                                   else:
                                        if fle in summary[key]:
                                             file_notes += " & yes"
                                        else:
                                             file_notes += " & no"
                              file_notes += "\\\\ \n \hline\n"
                    used_keys.append(current)
               file_notes += "\end{longtable}\n"
               file_notes += "\end{center}\n"
          except:
               raise CuckooReportError("Files issue: ", sys.exec_info()[0])
          finally:
               return file_notes

# Create table of accessed registries & what actions were performed on them
     def regactivity(self, results, procs):
          reg_notes = ""
          try:
               reg_notes += "\section{Registry Activity}\n"
               reg_notes += "\label{Registry Activity}\n"
               reg_notes += "\definecolor{MyRed}{rgb}{0.95,0,0}\n"
               reg_notes += "This section outlines all the interactions"
               reg_notes += " processes made with the registry. This allows"
               reg_notes += " analysts to see activity with the same registry"
               reg_notes += " spread across multiple processes. Entries in red"
               reg_notes += " were accessed by a process in the process tree"
               reg_notes += " started by the sample. These should be"
               reg_notes += " investigated further for changes.\n\n"
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
                              color = self.get_color(results, reg, procs)
                              reg_notes += color
                              reg2 = self.fix_slash(reg)
                              reg2 = self.fix_all(reg2)
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

# Section documenting various network connections 
     def network(self, results):
          net_notes = ""
          try:
               net_notes += "\section{Network Activity}\n"
               net_notes += "\label{Network Activity}\n"
               net_notes += "This section outlines the network connections "
               net_notes += "cuckoo observed during sample execution. These "
               net_notes += "include tcp and udp connections, dns queries, "
               net_notes += "dns servers, and websites visited. These should"
               net_notes += " be investigated on a case-by-case basis.\n\n"
               net_notes += "\\fbox{ \\begin{minipage}{15em}\n"
               net_notes += "This is a list of IP addresses which a process"
               net_notes += " tried to connect that cuckoo determined was "
               net_notes += "'dead'. This means it is either no longer "
               net_notes += "valid, or could not be reached. Having entries "
               net_notes += "here is very often an inidicator of malware."
               net_notes += "\\\\ \n"
               hosts = []
               for host in results['network']['dead_hosts']:
                    if host[0] not in hosts:
                         hosts.append(host[0])
               for host in hosts:
                    net_notes += host + "\n"
               net_notes += "\end{minipage} }\n"
               net_notes += "\\fbox{ \\begin{minipage}{15em}\n"
               net_notes += "These are the IPs of DNS servers that were used"
               net_notes += " for making DNS queries. These are not suspicious"
               net_notes += " outright, but should still be noted. \\\\ \n"
               for host in results['network']['dns_servers']:
                    net_notes += host + "\n"
               net_notes += "\end{minipage} }\n"
               net_notes += "\\fbox{ \\begin{minipage}{15em}\n"
               net_notes += "This section is a list of domains Cuckoo observed"
               net_notes += " connections being made to. These likely need to"
               net_notes += " be investigated, but do so carefully as they may"
               net_notes += " be malicous. \\\\ \n"
               for domain in results['network']['domains']:
                    net_notes += domain['domain'] + "\n"
               net_notes += "\end{minipage} }\n"
               net_notes += "\\fbox{ \\begin{minipage}{15em}\n"
               net_notes += "The following IPs made UDP connections with the"
               net_notes += " Cuckoo VM. They are not suspicious outright, but"
               net_notes += " should be used as a point of further"
               net_notes += " investigation. \\\\ \n"
               hosts = []
               for host in results['network']['udp']:
                    if host['dst'] not in hosts:
                         hosts.append(host['dst'])
               for host in hosts:
                    net_notes += host + "\n"
               net_notes += "\end{minipage} }\n"
               net_notes += "\\fbox{ \\begin{minipage}{15em}\n"
               net_notes += "The following IPs made TCP connections with the"
               net_notes += " Cuckoo VM. They are not suspicious outright, but"
               net_notes += " should be used as a point of further"
               net_notes += " investigation. \\\\ \n"
               hosts = []
               for host in results['network']['tcp']:
                    if host['dst'] not in hosts:
                         hosts.append(host['dst'])
               for host in hosts:
                    net_notes += host + "\n"
               net_notes += "\end{minipage} }\n"
          except:
               raise CuckooReportError("Network issue: ", sys.exec_info()[0])
          finally:
               return net_notes

# Main function that builds the base of the report & calls the other functions
     def run(self, results):
          try:
               global sample
               global sample_pure
               sample_pure = results['target']['file']['name']
               sample = self.fix_all(sample_pure)
               whole_doc = ""
               whole_doc += "\documentclass{report}\n"
               whole_doc += "\usepackage{tikz}\n"
               whole_doc += "\usepackage[a4paper, margin=1in]{geometry}\n"
               whole_doc += "\usepackage{pgfplots}\n"
               whole_doc += "\usepackage{longtable}\n"
               whole_doc += "\usepackage{color, colortbl}\n"
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
               whole_doc += results['info']['machine']['manager'] + " VM "
               time = results['info']['ended'] - results['info']['started']
               time = time.total_seconds()
               mins, sec = divmod(time, 60)
               hour, mins = divmod(mins, 60)
               strtime = "%d:%02d:%02d" % (hour, mins, sec)
               whole_doc += "for " + strtime  + ". "
               whole_doc += "It was given a score of "
               whole_doc += str(results['info']['score']) + ". "
               whole_doc += "The sections are: "
               whole_doc += "signatures, process tree, PE File, API Calls, "
               whole_doc += "File System Activity, Registry Activity.\n"
               (sigs, apis) = self.sig_analysis(results)
               whole_doc += sigs
               (trees, procs) = self.tree(results)
               whole_doc += trees
               whole_doc += self.pe_sec(results)
               whole_doc += self.apicalls(results, apis)
               whole_doc += self.fileactivity(results, procs)
               whole_doc += self.regactivity(results, procs)
               whole_doc += self.network(results)
               whole_doc += "\end{document}"
               alt_file_path = os.path.join(self.reports_path, "latex.txt")
               with open(alt_file_path, "w") as test_report:
                    test_report.write(whole_doc)
                    test_report.close()
          except (TypeError, IOError) as e:
               raise CuckooReportError("Didn't generate duncan report: %s" % e)     
