#!/usr/bin/python
##
## Copyright (c) 2015-2018 Nexenta Systems, inc.
##
## This file is part of EdgeFS Project
## (see https://github.com/Nexenta/edgefs).
##
## Licensed to the Apache Software Foundation (ASF) under one
## or more contributor license agreements.  See the NOTICE file
## distributed with this work for additional information
## regarding copyright ownership.  The ASF licenses this file
## to you under the Apache License, Version 2.0 (the
## "License"); you may not use this file except in compliance
## with the License.  You may obtain a copy of the License at
##
##   http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing,
## software distributed under the License is distributed on an
## "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
## KIND, either express or implied.  See the License for the
## specific language governing permissions and limitations
## under the License.
##

import sys
import getopt
import os
import fnmatch
import json
import time

FH_ARGS_MAX = 2
FH_FILE_PATTERN = 'flexhash.*.json'
FH_DIFF_CMD = '/usr/bin/diff -u'
FH_LOGFILE_START = 'flexhash'
FH_JSON_EXTN = '.json'
NEDGE_HOME = '/opt/nedge'
FH_VAR_LOG = '/var/run'

class FHTable:
    def __init__(self, dir):
        self.logdir = dir

    def load_json_fhdata(self, file):
        with open(file) as fh:
            self.fhdata = json.load(fh)

    def load_json_diff_files(self, ofidx, nfidx):
        oldfile = self.get_full_file_path(ofidx)
        newfile = self.get_full_file_path(nfidx)
        with open(oldfile) as fh:
            self.oldfhdata = json.load(fh)
        with open(newfile) as fh:
            self.newfhdata = json.load(fh)

        if self.oldfhdata['numrows'] != self.newfhdata['numrows']:
            print >> sys.stderr, 'Inconsistent hash!! Number of rows'
            print >> sys.stderr, 'don\'t match'

    def get_full_file_path(self, idx):
        file_path =  self.logdir + '/' + FH_LOGFILE_START + '.' + \
                     idx + FH_JSON_EXTN
        if os.path.exists(file_path):
            return file_path
        else:
            print 'Log file with id ' + idx + ' does not exist'
            sys.exit(2)

    def get_fhdata_value(self, value):
        return self.fhdata[value]

    def get_dev_rows(self, short_devid):
        rowlist = []
        for row in self.fhrows:
            if short_devid in row['rowmembers']:
                rowlist.append(row['rownum'])
        return rowlist

    def get_server_rows(self, devdict):
        l = []
        for rows in devdict.values():
            l.extend(rows)
        return list(set(l))

    def build_loglist(self):
        self.fileinfolist = []
        for file in os.listdir(self.logdir):
            if fnmatch.fnmatch(file, FH_FILE_PATTERN):
                filepath = self.logdir + '/' + file
                fileinfo = []
                fileinfo.append(os.path.getmtime(filepath))
                fileinfo.append(file)
                self.load_json_fhdata(filepath)
                desc_str = str(self.get_fhdata_value('desc'))
                fileinfo.append(['desc', desc_str])
                fileinfo.append(['genid',self.get_fhdata_value('genid')])
                fileinfo.append(['leader', self.get_fhdata_value('leader')])
                self.fileinfolist.append(fileinfo)
        self.fileinfolist = sorted(self.fileinfolist, reverse=True);

    def build_server_dict(self, args):
        self.load_json_fhdata(args)
        self.sdict = {}
        vdevlist = self.get_fhdata_value('vdevlist')
        self.fhrows = self.get_fhdata_value('rows')
        for row in range(self.get_fhdata_value('vdevcount')):
            srvid = str(vdevlist[row]['serverid'])
            devid = str(vdevlist[row]['vdevid'])
            devinfo = {devid : self.get_dev_rows(vdevlist[row]['short id'])}
            if self.sdict.has_key(srvid):
                self.sdict.get(srvid).update(devinfo)
            else:
                self.sdict[srvid] = devinfo

    def build_vdev_dict(self, args):
        self.load_json_fhdata(args)
        self.vdevdict = {}
        vdevlist = self.get_fhdata_value('vdevlist')
        for row in range(self.get_fhdata_value('vdevcount')):
            srvid = str(vdevlist[row]['serverid'])
            devid = str(vdevlist[row]['short id'])
            self.vdevdict[devid] = srvid

    def print_logentry(self, row, loginfo):
        printbuf = str(row) + '. ' if row > 0 else ''
        printbuf = printbuf + loginfo[1]
        printbuf = printbuf + '\n\t[' + time.ctime(loginfo[0]) + ']'
        for attr in loginfo[2:]:
            printbuf = printbuf + '\n\t' + str(attr)
        print printbuf
    
    def print_all_logentries(self):
        for idx in range(len(self.fileinfolist)):
            self.print_logentry(idx+1, self.fileinfolist[idx])

    def print_rowdiff(self, rownum):
        oldrow = self.oldfhdata['rows'][rownum]['rowmembers']
        newrow = self.newfhdata['rows'][rownum]['rowmembers']
        removed = list(set(oldrow).difference(set(newrow)))
        added = list(set(newrow).difference(set(oldrow)))
        print 'rownum:', rownum
        if added:
            print '+ ', json.dumps(added)
        if removed:
            print '- ', json.dumps(removed)

    def print_server_dict(self):
        if not self.fhdata:
            return

        print 'Servers:'
        numrows = self.get_fhdata_value('numrows')
        for server in self.sdict.keys():
            devdict = self.sdict.get(server)
            serverrows = self.get_server_rows(devdict)
            print 'Server: ', server, ': ', len(serverrows), '/', numrows
            print serverrows
            print '\tDevices:'
            for dev in devdict.keys():
                print '\t', dev, ':', len(devdict[dev]), '/', numrows
                print '\t', devdict[dev]
            print '\n'

    def show(self, args):
        self.build_loglist()
        self.print_all_logentries()

    def diff(self, args):
        self.load_json_diff_files(args[0], args[1])
        for rownum in range(int(self.oldfhdata['numrows'])):
            self.print_rowdiff(rownum)

    def summary(self, args):
        file = self.get_file_path(args)
        self.load_json_fhdata(file)
        print 'Log file: ' + file + '\n'
        print 'Hostname - ' + self.get_fhdata_value('hostname')
        print 'Generation Id - ' + str(self.get_fhdata_value('genid'))
        print 'Number of servers - ' + str(self.get_fhdata_value('servercount'))
        print 'Number of devices - ' + str(self.get_fhdata_value('vdevcount'))

    def rowdiffs(self, args):
        rownum = int(args[0])
        self.load_json_diff_files(args[1], args[2])

        if rownum not in range(int(self.oldfhdata['numrows'])):
            print >> sys.stderr, 'Row number ' + str(rownum) + ' not in hash'
        else:
            self.print_rowdiff(rownum)

    def exit_on_null_data(self):
        if not self.fileinfolist:
            print 'No log files in', self.logdir
            sys.exit(2)

    def get_file_path(self, args):
        if args:
            return self.get_full_file_path(args[0])
        else:
            self.build_loglist()
            self.exit_on_null_data()
            return self.logdir + '/' + self.fileinfolist[0][1]

    def rows(self, args):
        file = self.get_file_path(args)
        print file
        self.build_vdev_dict(file)
        fhrows = self.get_fhdata_value('rows')
        for row in fhrows:
            print 'rownum:', row['rownum'],
            print '\n\tdevcount:', row['numdevices']
            devlist = row['rowmembers']
            print '\tdevices:', json.dumps(devlist)
            print '\tReported servercount:', row['servercount']
            serverset = set()
            for dev in devlist:
                serverset.add(self.vdevdict[dev][:4])
            print '\tCalculated servercount (using devices):', len(serverset)
            print '\tservers:', list(serverset)

    def servers(self, args):
        file = self.get_file_path(args)
        print file
        self.build_server_dict(file)
        self.print_server_dict()

    def current(self, args):
        self.build_loglist()
        self.exit_on_null_data()
        self.print_logentry(0, self.fileinfolist[0])


cmd_funcs = {
        'current'   :   lambda object, args: object.current(args),
        'diff'      :   lambda object, args: object.diff(args),
        'help'      :   lambda object, args: usage(),
        'rows'      :   lambda object, args: object.rows(args),
        'rowdiffs'  :   lambda object, args: object.rowdiffs(args),
        'servers'   :   lambda object, args: object.servers(args),
        'show'      :   lambda object, args: object.show(args),
        'summary'   :   lambda object, args: object.summary(args),
}


def usage():
    print sys.argv[0], '--command=arguments'
    print 'Available commands : \n'
    for cmd in cmd_funcs:
        if cmd == 'diff':
            print '\t--' + cmd + '=<logfile-id1,logfile-id2>'
        elif cmd in ('summary', 'servers', 'rows'):
            print '\t--' + cmd + '=<logfile-id>'
        elif cmd == 'rowdiffs':
            print '\t--' + cmd + '=<row-id,logfile-id1,logfile-id2>'
        else:
            print '\t--' + cmd
    sys.exit(2)

def are_params_int(params):
    return all(p.isdigit() for p in params)

def main():
    if len(sys.argv) > FH_ARGS_MAX:
        usage()

    l = sys.argv[1].split('=')
    cmd = l[0]
    params = ''
    args = []

    if len(l) == 2:
        params = l[1]

    if params:
        args = params.split(',')

    if cmd == '--diff':
        if len(args) != 2 or not are_params_int(args):
            usage()
    elif cmd == '--rowdiffs':
        if len(args) != 3 or not are_params_int(args):
            usage()
    elif cmd == '-h':
        cmd = '--help'

    if cmd[2:] not in cmd_funcs:
        usage()

    log_dir = os.getenv('NEDGE_HOME', NEDGE_HOME) + FH_VAR_LOG
    fhtable = FHTable(log_dir)
    ret = cmd_funcs[cmd[2:]](fhtable, args)
    sys.exit(2 if ret != 0 else 0)

if __name__ == '__main__':
    main()
