#!/usr/bin/env python

import subprocess
import sys
import os
from optparse import OptionParser
import re
import StringIO
import numpy
import pandas
import random
import string
import glob

# Our interface to the GraphDB
from bulbs.rexster import Graph, Config, DEBUG

# Our own modules
from gh.connect import Connect
from gh.util import graph_info, shortest_path, edge_list
from db_stats import graph_stats

# A per-log dict that contains the list of fields we want to extract, in order
SUPPORTED_BRO_FIELDS = {
    "conn.log": ["ts","uid","id.orig_h","id.orig_p","id.resp_h","id.resp_p","proto","service","duration","orig_bytes","resp_bytes","conn_state","local_orig","missed_bytes","history","orig_pkts","orig_ip_bytes","resp_pkts","resp_ip_bytes","tunnel_parents"],
    "dns.log":["ts","uid","id.orig_h","id.orig_p","id.resp_h","id.resp_p","proto","trans_id","query","qclass","qclass_name","qtype","qtype_name","rcode","rcode_name","AA","TC","RD","RA","Z","answers","TTLs","rejected"],
    "dpd.log": ["ts","uid","id.orig_h","id.orig_p","id.resp_h","id.resp_p","proto","analyzer","failure_reason"],
    "files.log": ["ts","fuid","tx_hosts","rx_hosts","conn_uids","source","depth","analyzers","mime_type","filename","duration","local_orig","is_orig","seen_bytes","total_bytes","missing_bytes","overflow_bytes","timedout","parent_fuid","md5","sha1","sha256","extracted"],
    "ftp.log": ["ts","uid","id.orig_h","id.orig_p","id.resp_h","id.resp_p","user","password","command","arg","mime_type","file_size","reply_code","reply_msg","data_channel.passive","data_channel.orig_h","data_channel.resp_h","data_channel.resp_p","fuid"],
    "http.log": ["ts","uid","id.orig_h","id.orig_p","id.resp_h","id.resp_p","trans_depth","method","host","uri","referrer","user_agent","request_body_len","response_body_len","status_code","status_msg","info_code","info_msg","filename","tags","username","password","proxied","orig_fuids","orig_mime_types","resp_fuids","resp_mime_types"],
    "irc.log": ["ts","uid","id.orig_h","id.orig_p","id.resp_h","id.resp_p","nick","user","command","value","addl","dcc_file_name","dcc_file_size","dcc_mime_type","fuid"],
    "notice.log": ["ts","uid","id.orig_h","id.orig_p","id.resp_h","id.resp_p","fuid","file_mime_type","file_desc","proto","note","msg","sub","src","dst","p","n","peer_descr","actions","suppress_for","dropped","remote_location.country_code","remote_location.region","remote_location.city","remote_location.latitude","remote_location.longitude"],
    "smtp.log": ["ts","uid","id.orig_h","id.orig_p","id.resp_h","id.resp_p","trans_depth","helo","mailfrom","rcptto","date","from","to","reply_to","msg_id","in_reply_to","subject","x_originating_ip","first_received","second_received","last_reply","path","user_agent","tls","fuids","is_webmail"],
    "snmp.log": ["ts","uid","id.orig_h","id.orig_p","id.resp_h","id.resp_p","duration","version","community","get_requests","get_bulk_requests","get_responses","set_requests","display_string","up_since"],
    "ssh.log": ["ts","uid","id.orig_h","id.orig_p","id.resp_h","id.resp_p","status","direction","client","server","remote_location.country_code","remote_location.region","remote_location.city","remote_location.latitude","remote_location.longitude"],
    "pe.log":["ts","id","machine","compile_ts","os","subsystem","is_exe","is_64bit","uses_aslr","uses_dep","uses_code_integrity","uses_seh"	,"has_import_table","has_export_table","has_cert_table","has_debug_data","section_names"]
}

FIELDS_STRING = ["TTLs"]
FIELDS_INTEGER = ["id.orig_p","id.resp_p","orig_bytes","resp_bytes","missed_bytes","orig_pkts","orig_ip_bytes","resp_pkts","resp_ip_bytes","qclass","qtype","trans_id","rcode","Z","depth","seen_bytes","total_bytes","file_size","reply_code","data_channel.resp_p","trans_depth","request_body_len","response_body_len","status_code","info_code","dcc_file_size"]
FIELDS_FLOAT = ["duration","lease_type"]
FIELDS_LONG = ["missing_bytes"]

# Output date format for timestamps
DATE_FMT="%FT%H:%M:%SZ"

BRO_CUT_CMD=["bro-cut","-U",DATE_FMT]

def unique_id(size=17):
    return ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for _ in range(size))

def is_IP(s):
    # this is pretty dumb.  If it looks like an IPv4 address, fine.  But a
    # good IPv6 regex is ridiculously complex.  I took a shortcut, since I
    # this routine is only ever called to disambiguate IPs from hostnames or
    # FQDNs.  If there's even a single ":", we'll just assume this must be
    # IPv6, since neither hostnames nor FQDNs can contain that char.
    #
    # Sorry.
    return( re.match("\d+.\d+.\d+.\d+$", s) != None or re.search(":",s) != None)


def extend_list(lst, val, length):
    '''
    Given a list "lst", extend it to length "length".  Each new item will
    be composed of the value "val".  Of course, if "lst" is already "length"
    size or longer, just return and do nothing.
    '''
    if len(lst) >= length:
        return lst
    else:
        lst.extend([val] * (length - len(lst)))
        return lst

def parse_options() :
    parser = OptionParser()
    parser.add_option("-l", "--log-dir", dest="logdir",
                      help="Bro log file directory to parse.")
    parser.add_option("-q", "--quiet", dest="quiet",
                      help="Suppress unecessary output (run quietly)")
    parser.add_option("-o", "--output", dest="outputdir",default=".",
                      help="Output directory (will be created if necessary)")
    parser.add_option("-s", "--sample", dest="sample",default=False,type="int",
                      help="Randomly select SAMPLE # of connections and associated log entries.")
    parser.add_option("-t", "--time", dest="time",
                      help="Bro log time to parse, like 00:00:00-01:00:00")

    (options, args) = parser.parse_args()
    return(options, args)

def readlog(file, connection_ids=False):

    output = ""

    logtype = file

    logfile = "%s/%s" % (options.logdir, file)

    print "Reading %s..." % logfile

    tmp_bro_cut_cmd = BRO_CUT_CMD
    tmp_bro_cut_cmd = tmp_bro_cut_cmd + SUPPORTED_BRO_FIELDS[logtype]

    # Create a job that just cats the log file
    p1 = subprocess.Popen(['cat',logfile], stdout=subprocess.PIPE)

    # This is the bro-cut job, reading the "cat" command output
    p2 = subprocess.Popen(tmp_bro_cut_cmd, stdin=p1.stdout, stdout=subprocess.PIPE)

    p1.stdout.close()

    # Now we're going to use the "pandas" package to create a dataframe
    # out of the log data.  Dataframes greatly simplify the tasks of cleaning
    # the data.
    #
    # StringIO treats the string as a fake file, so we can use pandas to
    # create a dataframe out of the string directly, without having to write
    # it to disk first.
    brodata = StringIO.StringIO(p2.communicate()[0])

    df = pandas.DataFrame.from_csv(brodata, sep="\t", parse_dates=False, header=None, index_col=None)

    df.columns = SUPPORTED_BRO_FIELDS[logtype]

    # If this is the connection log, and if we've requested a random sample,
    # cut the dataframe down to ONLY contain that random sample
    if logtype == "conn.log" and options.sample:
        print "Size before sampling: %d" % len(df.index)
        df = df.sample(n=options.sample)
        df.reset_index(drop=True, inplace=True)
        print "Size after sampling: %d" % len(df.index)
    elif logtype == "files.log" and connection_ids:
        df = df[df.conn_uids.isin(connection_ids)]
        df.reset_index(drop=True, inplace=True)
    elif logtype != "conn.log" and connection_ids and "uid" in df.columns:
        # If this is any other type of log AND we have an explicit list of
        # connection IDs we sampled AND this is a file that has the "uid"
        # data to pair it with the conn.log, pare down the dataframe to
        # only include those rows with the right uids
        df = df[df.uid.isin(connection_ids)]
        df.reset_index(drop=True, inplace=True)
        # It is entirely possible that this sampling may mean that some
        # log files no longer have any output (for example, you only sampled
        # a list of connections, none of which were DHCP).

    df.replace(to_replace=["(empty)","-"], value=["",""], inplace=True)

    # Some columns need to be forced into type String, primarily because they
    # may contain lists and we always call split() on them, but they look like
    # integers, so numpy tries to store them that way.
    for field in FIELDS_STRING:
        if field in df.columns:
            df[field] = df[field].astype(str)

    # Likewise, many rows need to be stored as Integers, but numpy thinks
    # they may be strings (probably because a legal value is "-").  This is
    # the list of the fields we know need to be converted
    for field in FIELDS_INTEGER:
        if field in df.columns:
            df[field] = df[field].replace("",-1)
            df[field] = df[field].astype(int)

    # Finally, convert the Float fields
    for field in FIELDS_FLOAT:
        if field in df.columns:
            df[field] = df[field].replace("",numpy.nan)
            df[field] = df[field].astype(float)

    #for field in FIELDS_LONG:
    #    if field in df.columns:
    #        df[field] = df[field].replace("", -1)
    #        df[field] = df[field].astype(long)

    if logtype == "conn.log":
        # if we're processing the conn.log AND we've requested random samples,
        # create a list of the sampled connection IDs and update the
        # connection_ids parameter.  Otherwise, leave it the same.
        if options.sample:
            for id in df["uid"].tolist():
                connection_ids.append(id)

    return df

def graph_flows(g, df_conn):
    # Iterate through all the flows
    for con in df_conn.index:

        flowname = df_conn.loc[con]["uid"]
        # Create the flow node, with all the rich data
        properties = dict(df_conn.loc[con])
        # Manually assign the "name" property
        properties["name"] = flowname


        flow = g.flow.get_or_create("name", flowname, properties)


def graph_dns(g, df_dns):
    # Iterate through all the flows
    for i in df_dns.index:
        # Create the DNSTransaction node
        # name = str(df_dns.loc[i]["trans_id"])
        name = "%d - %s - %s" % (df_dns.loc[i]["trans_id"],
                                 df_dns.loc[i]["qtype_name"],
                                 df_dns.loc[i]["query"])
        timestamp = df_dns.loc[i]["ts"]
        flowname = df_dns.loc[i]["uid"]

        # Pick out the properties that belong on the transaction and add
        # them
        transaction = g.dnsTransaction.create(name=name,
                                              ts=df_dns.loc[i]["ts"],
                                              proto=df_dns.loc[i]["proto"],
                                              orig_p=df_dns.loc[i]["id.orig_p"],
                                              resp_p=df_dns.loc[i]["id.resp_p"],
                                              qclass=df_dns.loc[i]["qclass"],
                                              qclass_name=df_dns.loc[i]["qclass_name"],
                                              qtype=df_dns.loc[i]["qtype"],
                                              qtype_name=df_dns.loc[i]["qtype_name"],
                                              rcode=df_dns.loc[i]["rcode"],
                                              rcode_name=df_dns.loc[i]["rcode_name"],
                                              AA=df_dns.loc[i]["AA"],
                                              TC=df_dns.loc[i]["TC"],
                                              RD=df_dns.loc[i]["RD"],
                                              RA=df_dns.loc[i]["RA"],
                                              Z=df_dns.loc[i]["Z"],
                                              rejected=df_dns.loc[i]["rejected"])

        # Create a node + edge for the query, if there is one in the log
        if df_dns.loc[i]["query"]:
            fqdn = g.fqdn.get_or_create("name", df_dns.loc[i]["query"],
                                        {"name":df_dns.loc[i]["query"],
                                         "domain":df_dns.loc[i]["query"]})
            g.lookedUp.create(transaction,fqdn)

            # Now create the nodes and edges for the domains or addresses in
            # the answer (if there is an answer).  There can be multiple
            # answers, so split this into a list and create one node + edge
            # for each.
            #
            # There should also be one TTL per answer, so we'll split those and
            # use array indices to tie them together. The arrays are supposed
            # to always be the same length, but maybe sometimes they are
            # not.  We'll force the issue by extending the TTL list to be
            # the same size as the address list.
            if df_dns.loc[i]["answers"]:
                addrs = df_dns.loc[i]["answers"].split(",")
                ttls = df_dns.loc[i]["TTLs"].split(",")
                ttls = extend_list(ttls, ttls[len(ttls)-1],len(addrs))

                for i in range(len(addrs)):
                    ans = addrs[i]
                    ttl = float(ttls[i])
                    # DNS answers can be either IPs or other names. Figure
                    # out which type of node to create for each answer.
                    if is_IP(ans):
                        node = g.host.get_or_create("name",ans,{"name":ans,
                                                                "address":ans})
                    else:
                        node = g.fqdn.get_or_create("name",ans,{"name":ans,
                                                                "address":ans})

                    g.resolvedTo.create(fqdn, node, {"ts":timestamp})
                    g.answer.create(transaction, node, {"TTL": ttl})

        # Create a node + edge for the source of the DNS transaction
        # (the client host)
        if df_dns.loc[i]["id.orig_h"]:
            src = g.host.get_or_create("name", df_dns.loc[i]["id.orig_h"],
                                       {"name": df_dns.loc[i]["id.orig_h"],
                                        "address":df_dns.loc[i]["id.orig_h"]})
            g.queried.create(src, transaction)

        # Create a node + edge for the destination of the DNS transaction
        # (the DNS server)
        if df_dns.loc[i]["id.resp_h"]:
            dst = g.host.get_or_create("name", df_dns.loc[i]["id.resp_h"],
                                       {"name": df_dns.loc[i]["id.resp_h"],
                                        "address":df_dns.loc[i]["id.resp_h"]})
            g.queriedServer.create(transaction,dst)


        # Now connect this transaction to the correct flow
        flows = g.flow.index.lookup(name=flowname)
        if flows == None:
            # print "ERROR: Flow '%s' does not exist" % flowname
            pass
        else:
            # lookup returns a generator, but since there should only be one
            # flow with this name, just take the first one
            flow = flows.next()
            nodes = flow.outV("contains")
            if nodes == None or not (transaction in nodes):
                edge = g.contains.create(flow, transaction)


        # Associate the src host with the FQDN it resolved.  Since a host
        # can resolve a domain multiple times, we'll also keep track of a
        # "weight" feature to count how many times this happened.
        if df_dns.loc[i]["query"]:
            neighbors = src.outV("resolved")
            if neighbors == None or not (fqdn in neighbors):
                e = g.resolved.create(src, fqdn)
                e.weight=1
                e.save()
            else:
                edges = edge_list(g, src._id, fqdn._id, "resolved")
                # There should only be one of these edges, and we already know
                # it exists, so it's safe to just take the first one
                edge = edges.next()
                g.resolved.update(edge._id, weight=(edge.weight + 1))

def graph_files(g, df_files):
    # Iterate through all the flows
    for i in df_files.index:
        # Create the file node
        name = str(df_files.loc[i]["fuid"])
        timestamp = df_files.loc[i]["ts"]
        flows = df_files.loc[i]["conn_uids"]

        # Create the file object. Note that this is more like a file transfer
        # transaction than a static object just for that file.  There can be
        # more than one node with the same MD5 hash, for example.  Cleary,
        # those are the same file in the real world, but not in our graph.
        #
        # However, it is possible to actually have the same file transaction
        # show up in the Bro logs multiple times.  AFAICT, this is mostly
        # due to things like timeouts, where Bro records the file transfer
        # start and then sends another log later that says that the xfer
        # failed.  We need to make sure we always check to make sure there
        # is only one File node for each actual transaction, but we'll use
        # the fields from the most recent log, assuming things that Bro
        # logs last will be more accurate.
        fileobj = g.file.get_or_create("name", name, {"name":name})

        fileobj.fuid=df_files.loc[i]["fuid"]
        fileobj.source=df_files.loc[i]["source"]
        fileobj.depth=df_files.loc[i]["depth"]
        fileobj.analyzers=df_files.loc[i]["analyzers"]
        fileobj.mime_type=df_files.loc[i]["mime_type"]
        fileobj.filename=df_files.loc[i]["filename"]
        fileobj.duration=df_files.loc[i]["duration"]
        fileobj.seen_bytes=df_files.loc[i]["seen_bytes"]
        fileobj.total_bytes=df_files.loc[i]["total_bytes"]
        fileobj.missing_bytes=df_files.loc[i]["missing_bytes"]
        fileobj.overflow_bytes=df_files.loc[i]["overflow_bytes"]
        fileobj.timedout=df_files.loc[i]["timedout"]
        fileobj.md5=df_files.loc[i]["md5"]
        fileobj.sha1=df_files.loc[i]["sha1"]
        fileobj.sha256=df_files.loc[i]["sha256"]
        fileobj.extracted=df_files.loc[i]["extracted"]
        fileobj.save()

        pe = g.pe.get_or_create("name",name,{"name":name})
        g.transferred.create(pe, fileobj)

        # Now connect this to the flow(s) it is associated with.
        for f in flows.split(","):
            flow = g.flow.get_or_create("name", f, {"name": f})
            g.contains.create(flow, fileobj)

def graph_http(g, df_http):
    # Iterate through all the flows
    for i in df_http.index:
        # Create the HTTPTransaction node
        http = g.httpTransaction.create(name="H" + unique_id(),
                                        ts=df_http.loc[i]["ts"],
                                        host=df_http.loc[i]["host"],
                                        uri=df_http.loc[i]["uri"],
                                        orig_h=df_http.loc[i]["id.orig_h"],
                                        orig_p=df_http.loc[i]["id.orig_p"],
                                        resp_h=df_http.loc[i]["id.resp_h"],
                                        resp_p=df_http.loc[i]["id.resp_p"],
                                        trans_depth=df_http.loc[i]["trans_depth"],
                                        method=df_http.loc[i]["method"].upper(),
                                        request_body_len=df_http.loc[i]["request_body_len"],
                                        response_body_len=df_http.loc[i]["response_body_len"],
                                        status_code=df_http.loc[i]["status_code"],
                                        status_msg=df_http.loc[i]["status_msg"],
                                        info_code=df_http.loc[i]["info_code"],
                                        info_msg=df_http.loc[i]["info_msg"],
                                        filename=df_http.loc[i]["filename"],
                                        tags=df_http.loc[i]["tags"],
                                        proxied=df_http.loc[i]["proxied"])

        # Now connect this to the flow it's associated with
        flowname = df_http.loc[i]["uid"]
        flow = g.flow.get_or_create("name", flowname, {"name":flowname})
        g.contains.create(flow, http)



def graph_pe(g,df_pe):
    for i in df_pe.index:
        name = df_pe.loc[i]["id"]
        peobj = g.pe.get_or_create("name",name,
                                   name=name,
                                   ts=df_pe.loc[i]["ts"],
                                   machine=df_pe.loc[i]["machine"],
                                   compile_ts=df_pe.loc[i]["compile_ts"],
                                   os=df_pe.loc[i]["os"],
                                   subsystem=df_pe.loc[i]["subsystem"])

def graph_edges2file(g,df_files):
    name = str(df_files.loc[i]["fuid"])
    flows = df_files.loc[i]["conn_uids"]
    fileobj = g.file.get_or_create("name", name, {"name": name})
    # Now connect this to the flow(s) it is associated with.
    for f in flows.split(","):
        flow = g.flow.get_or_create("name", f, {"name": f})
        g.contains.create(flow, fileobj)

##### Main #####

(options, args) = parse_options()

if not options.logdir:
    print "Error: Must specify the log directory with -l or --log-dir"
    sys.exit(-1)

if not options.time:
    print "Error: Must specify the time period of log with -t or --time, like 00:00:00-01:00:00"
    sys.exit(-1)

if not os.path.exists(options.logdir):
    print "Error: Directory %s does not exist" % options.logdir
    sys.exit(-1)

if not os.path.exists(options.outputdir):
    os.mkdir(options.outputdir)

if not options.quiet:
    print "Reading log files from %s" % options.logdir

# Now we can start to read data and populate the graph.

g = Connect()

# Now read the types of logs we know how to process, extract the relevant
# data and add it to the graph

connection_ids = list()


print "Graphing Pes..."
df_pe = readlog('pe.log', connection_ids)
print "Number of events: %d" % len(df_pe.index)
graph_pe(g, df_pe)

print "Graphing Files..."
fileheader = open('pelog/fileheader', 'r')
filelog = open('pelog/files.log', 'w')
filelog.write(fileheader.read())
fileheader.close()
filelog.close()
for i in df_pe.index:
    #use grep to find fid in files.log and make new filelog
    #print df_pe.loc[i]["id"]
    p1 = subprocess.Popen(['grep', df_pe.loc[i]["id"], 'pelog/files.'+options.time+'.log'], stdout=subprocess.PIPE)
    filelog = open('pelog/files.log', 'a')
    filelog.write(p1.stdout.read())
    p1.stdout.close()
    filelog.close()

df_files = readlog("files.log", connection_ids)
print "Number of events: %d" % len(df_files.index)
graph_files(g, df_files)

print "Graphing Flows and Http..."

connheader = open('pelog/connheader', 'r')
connlog = open('pelog/conn.log', 'w')
connlog.write(connheader.read())
connheader.close()
connlog.close()

httpheader = open('pelog/httpheader', 'r')
httplog = open('pelog/http.log', 'w')
httplog.write(httpheader.read())
httpheader.close()
httplog.close()

for j in df_files.index:
    flows = df_files.loc[j]["conn_uids"]
    for f in flows.split(','):
        p2 = subprocess.Popen(['grep', f, 'pelog/conn.'+options.time+'.log'],
                                  stdout=subprocess.PIPE)
        connl = open('pelog/conn.log', 'a')
        connl.write(p2.stdout.read())
        p2.stdout.close()
        connl.close()

        p3 = subprocess.Popen(['grep', f, 'pelog/http.'+options.time+'.log'],
                              stdout=subprocess.PIPE)
        httpl = open('pelog/http.log', 'a')
        httpl.write(p3.stdout.read())
        p3.stdout.close()
        httpl.close()

df_conn = readlog("conn.log", connection_ids)
graph_flows(g, df_conn)

#import pdb
#pdb.set_trace()
df_http = readlog("http.log", connection_ids)
graph_http(g, df_http)

graph_edges2file(g, df_files)

#print "Number of events: %d" % len(df_conn.index)+len(df_http.index)

#graph_http(g, df_http)

# Print some basic info about the graph so we know we did some real work
#graph_stats(g)
