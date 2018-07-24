#!/usr/bin/env python
# PYTHON_ARGCOMPLETE_OK
import argparse
import os
import pickle
import subprocess
import json

import argcomplete
import requests

# Copyright (c) 2016 Cisco Systems, Inc. and others.  All rights reserved.
#
# This program and the accompanying materials are made available under the
# terms of the Eclipse Public License v1.0 which accompanies this distribution,
# and is available at http://www.eclipse.org/legal/epl-v10.html
__author__ = 'mamihale@cisco.com'

sxpd_path = './sxpd'
verbosity = False


def un_quote(line, *values):
    for value in values:
        line = line.replace('"' + value + '"', value)
    return line


def add_quote(line, *values):
    for value in values:
        line = line.replace(value, '"' + value + '"')
    return line


def get_reverse_connection_mode(mode):
    mode = parse_mode(mode)
    if mode == "listener":
        return "speaker"
    elif mode == "speaker":
        return "listener"
    else:
        return "both"


def parse_mode(mode):
    if mode == "listener" or mode == 'l':
        return "listener"
    elif mode == "speaker" or mode == 's':
        return "speaker"
    elif mode == "both" or mode == 'b':
        return "both"
    if verbosity:
        print("ERROR parsing mode")


def parse_version(version):
    for v in [1, 2, 3, 4]:
        if version == "version" + str(v) or version == str(v) or version == v:
            return "version" + str(v)
    if verbosity:
        print("ERROR parsing version using version4")
    return 'version4'


class SXPD:
    pid = None

    def __init__(self, ip, node_id, initializer=None, port=64999, passowrd='none', enabled=True):
        if initializer is not None:
            self.config = initializer['config']
            self.bindings = initializer['bindings']
            self.peers = initializer['peers']
        else:
            self.config = {
                'retry_timer': 8,
                'reconciliation_timer': 120,
                'listener_min_hold_time': 90,
                'listener_max_hold_time': 180,
                'speaker_min_hold_time': 90,
                'keepalive_timer': 60,
                'subnet_expansion_limit': 50,
                'port_number': port,
                'bind_ip': ip,
                'enabled': enabled.__str__().upper()
            }
            if passowrd != 'none':
                self.config['default_connection_password'] = passowrd
            self.bindings = []
            self.peers = []
        self.config['node_id'] = hex(node_id)

    def get_id(self):
        return self.config['node_id']

    def get_ip(self):
        return self.config["bind_ip"]

    def get_port(self):
        return self.config['port_number']

    def get_password(self):
        return None if 'default_connection_password' not in self.config else \
            self.config['default_connection_password']

    def add_binding(self, sgt, prefix):
        ip_v = '4'
        if ':' in prefix:
            ip_v = '6'
        self.bindings.append({
            'ipv' + ip_v + '_prefix': prefix.split('/')[0],
            'ipv' + ip_v + '_prefix_length': int(prefix.split('/')[1]),
            'sgt': int(sgt)
        })

    def remove_binding(self, sgt, prefix):
        ip_v = '4'
        if ':' in prefix:
            ip_v = '6'
        self.bindings.remove({
            'ipv' + ip_v + '_prefix': prefix.split('/')[0],
            'ipv' + ip_v + '_prefix_length': int(prefix.split('/')[1]),
            'sgt': int(sgt)
        })

    def add_connection(self, mode, ip, password='none'):
        # TODO ip:port for ipv6
        connection_ = {
            'ip_address': ip.split(':')[0],
            'port_number': 64999 if len(ip.split(':')) == 1 else int(ip.split(':')[1]),
            'peer_type': mode
        }
        if password != 'none':
            connection_['connection_password'] = password
        self.peers.append(connection_)

    def remove_connection(self, mode, ip, password='none'):
        # TODO ip:port for ipv6
        connection_ = {
            'ip_address': ip.split(':')[0],
            'port_number': 64999 if len(ip.split(':')) == 1 else int(ip.split(':')[1]),
            'peer_type': mode
        }
        if password != 'none':
            connection_['connection_password'] = password
        self.peers.remove(connection_)

    def start_deamon(self, odl_=None):
        if self.pid is None:
            if verbosity:
                print('Starting sxpd with config:')
                print(json.dumps(self.config, indent=4))
            path = '/tmp/node_' + str(self.get_id()) + '.cfg'
            self.export(path)
            with open("/tmp/sxpd_node_" + str(self.get_id()) + ".log", "w") as f:
                self.pid = subprocess.Popen([sxpd_path, path, "debug", "/tmp/" + str(self.get_id()) + ".pid"],
                                            stdout=f, stderr=f).pid
            if verbosity:
                print('Process started with PID:' + str(self.pid))
            if odl_ is not None:
                for connection_ in self.peers:
                    if odl_.get_ip() == connection_['ip_address']:
                        odl_.add_connection(self.get_ip(), self.get_port(), connection_['peer_type'],
                                            password=self.get_password() if 'connection_password' not in connection_
                                            else connection_['connection_password'])
        elif verbosity:
            print('Process already started with PID:' + str(self.pid))

    def stop_deamon(self, odl_=None):
        if self.pid is not None:
            if verbosity:
                print('Killing process with PID:' + str(self.pid))
            subprocess.Popen(['kill', str(self.pid)])
            self.pid = None
            if odl_ is not None:
                for connection_ in self.peers:
                    if odl_.get_ip() == connection_['ip_address']:
                        odl_.remove_connection(self.get_ip(), self.get_port())
        elif verbosity:
            print('Process not running')

    def update_deamon(self):
        if self.pid is not None:
            subprocess.Popen(['kill', '-HUP', str(self.pid)])

    def status(self):
        print('Global ' + json.dumps(self.config, indent=4))
        print('Peers')
        self.connection_status()
        print('Bindings')
        self.master_database()
        if self.pid is not None and check_procces(self.pid):
            print('\033[92m' + 'Running PID ' + str(self.pid) + '\033[0m')
        else:
            if self.pid is not None:
                self.pid = None
            print('\033[91m' + 'Not running' + '\033[0m')

    def connection_status(self):
        peers_status = {}
        if self.pid is not None and check_procces(self.pid):
            with open("/tmp/sxpd_node_" + str(self.get_id()) + ".log", "r") as logs:
                for line in logs:
                    if 'Change outgoing connection state' in line:
                        peer = line.strip().split()[2].split('[')[0].split(':')[0]
                        if peer not in peers_status:
                            peers_status[peer] = {}
                        peers_status[peer]['status'] = line.strip().split('[')[-1].split('>')[-1][:-1]
                    elif 'Processing OPEN message' in line or 'Processing OPEN_RESP message' in line:
                        peer = line.strip().split()[2].split('[')[0].split(':')[0]
                        if peer not in peers_status:
                            peers_status[peer] = {}
                        peers_status[peer]['status'] = 'CONNECTED'
        for peer in self.peers:
            address = peer['ip_address']
            for k, v in peer.iteritems():
                if 'ip_address' not in k:
                    if address not in peers_status:
                        peers_status[address] = {}
                    peers_status[address][k] = v
        print json.dumps(peers_status, indent=4, separators=('', ' : '), sort_keys=True)

    def master_database(self):
        sxp_db = {}
        master_db = {}
        if self.pid is not None and check_procces(self.pid):
            with open("/tmp/sxpd_node_" + str(self.get_id()) + ".log", "r") as logs:
                peer = "NONE"
                for line in logs:
                    if 'sxpd_peer_add_prefix' in line.lower() and 'Peer' in line:
                        peer = line.strip().split()[2].split('[')[0]
                        if peer not in sxp_db:
                            sxp_db[peer] = {}
                    elif 'sxpd_peer_delete_all_bindings' in line.lower():
                        peer = line.strip().split()[2].split('[')[0]
                        if peer in sxp_db:
                            del sxp_db[peer]
                    elif 'sxpd_peer_add_prefix' in line.lower() and 'stored' in line.lower():
                        sxp_db[peer][line.strip().split()[-3]] = line.strip().split()[-1]
                    elif 'sxpd_peer_del_prefix' in line.lower() and 'deleting' in line.lower():
                        del sxp_db[peer][line.strip().split()[-3]]
        for p, db in sxp_db.iteritems():
            for prefix, sgt in db.iteritems():
                master_db[prefix] = sgt
        for b in self.bindings:
            if 'ipv4_prefix' in b:
                master_db[b['ipv4_prefix'] + '/' + str(b['ipv4_prefix_length'])] = str(b['sgt'])
            elif 'ipv6_prefix' in b:
                master_db[b['ipv6_prefix'] + '/' + str(b['ipv6_prefix_length'])] = str(b['sgt'])
        print json.dumps(master_db, indent=4, separators=('', ' : '), sort_keys=True)

    def export(self, path=None):
        if path is None:
            path = './node_' + str(self.get_id()) + '.cfg'
        global_ = "global = " + json.dumps(self.config, indent=4, separators=('', ' : '), sort_keys=True).replace(
            '"', '').replace(self.config['bind_ip'], '"' + self.config['bind_ip'] + '"') + ";\n"
        peers = "peers = " + json.dumps(self.peers, indent=4, separators=('', ' : '), sort_keys=True).replace(
            '[', '(').replace(']', ')').replace('}\n ', '},\n ') + ";\n"
        bindings = "bindings = " + json.dumps(self.bindings, indent=4, separators=('', ' : '), sort_keys=True).replace(
            '[', '(').replace(']', ')').replace('}\n ', '},\n ') + ";"

        data = global_ + un_quote(peers, 'connection_password', 'port_number', 'peer_type', 'ip_address')
        data += un_quote(bindings, 'ipv6_prefix_length', 'ipv4_prefix_length', 'ipv6_prefix', 'ipv4_prefix', 'sgt')
        with open(path, "w") as f:
            f.write(data)


class ODL:
    def __init__(self, ip, port, id_, user='admin', password='admin'):
        self.ip = ip
        self.id = id_
        self.auth = (user, password)
        self.port = port

    def get_ip(self):
        return self.ip

    def get_port(self):
        return self.port

    def status(self):
        print('ODL ip:port ' + self.get_ip() + ':' + str(self.get_port()))
        print('ODL id ' + self.id)

    def add_connection(self, peer_address, tcp_port, mode, version_='version4', password=None):
        if verbosity:
            print('REST to ' + self.ip + ' ID:' + self.id + ' addConneciton ' + peer_address + ':' + str(
                tcp_port) + ' mode:' + mode + ' version:' + version_ + ' password:' + (password if password else "N/A"))
        return self.post_to_odl('restconf/operations/sxp-controller:add-connection', {
            "input": {
                "requested-node": self.id,
                "connections": {
                    "connection": {
                        "peer-address": peer_address,
                        "tcp-port": tcp_port,
                        "password": password,
                        "mode": mode,
                        "version": version_,
                        "connection-timers": {
                            "hold-time-min-acceptable": "45",
                            "keep-alive-time": "30",
                            "reconciliation-time": "120"
                        }
                    }
                }
            }
        })

    def remove_connection(self, peer_address, tcp_port):
        if verbosity:
            print('REST to ' + self.ip + ' ID:' + self.id + ' removeConneciton ' + peer_address +
                  ':' + str(tcp_port))
        return self.post_to_odl('restconf/operations/sxp-controller:delete-connection', {
            "input": {
                "requested-node": self.id,
                "peer-address": peer_address,
                "tcp-port": tcp_port
            }
        })

    def get_connection(self, peer_address, tcp_port):
        if verbosity:
            print('REST to ' + self.ip + ' ID:' + self.id + ' getConneciton ' + peer_address + ':' + str(tcp_port))
        resp = json.load(self.post_to_odl('restconf/operations/sxp-controller:get-connections', {
            "input": {
                "requested-node": self.id
            }
        }))

    def post_to_odl(self, path, payload):
        data = json.dumps(payload)
        try:
            return requests.post('http://' + self.ip + ':8181/' + path, auth=self.auth,
                                 headers={'accept': 'application/json', 'content-type': 'application/json'},
                                 data=data).text
        except (requests.exceptions.ConnectionError, requests.ConnectionError):
            print('\033[91m' + 'ODL is down cannot make requests' + '\033[0m')

    def get_from_odl(self, path):
        try:
            return requests.get('http://' + self.ip + ':8181/' + path, auth=self.auth,
                                headers={'accept': 'application/json', 'content-type': 'application/json'}).text
        except (requests.exceptions.ConnectionError, requests.ConnectionError):
            print('\033[91m' + 'ODL is down cannot make requests' + '\033[0m')


def check_procces(pid):
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    else:
        return True


def import_config(f):
    if f is None:
        return None
    part = None
    global_ = '{\n'
    peers_ = '[\n'
    bindings_ = '[\n'
    for line in f:
        if 'global' in line:
            part = 'global'
            continue
        elif 'peers' in line:
            part = 'peers'
            continue
        elif 'bindings' in line:
            part = 'bindings'
            continue

        if part == 'global' and '}' not in line:
            global_ += '"' + add_quote(line, 'TRUE', 'FALSE').strip(' \t'). \
                replace('\n', ',\n' if 'node_id' not in line else '",\n'). \
                replace(' : ', '" : ' if 'node_id' not in line else '" : "')
        elif part == 'peers' and ')' not in line:
            if '{' in line or '}' in line:
                peers_ += line.strip(' \t')
            else:
                peers_ += '"' + line.strip(' \t').replace('\n', ',\n').replace(' :', '" :')
        elif part == 'bindings' and ')' not in line:
            if '{' in line or '}' in line:
                bindings_ += line.strip(' \t')
            else:
                bindings_ += '"' + line.strip(' \t').replace('\n', ',\n').replace(' :', '" :')

    global_ = (global_ + '}').replace(',\n}', '\n}')
    peers_ = (peers_ + ']').replace(',\n}', '\n}')
    bindings_ = (bindings_ + ']').replace(',\n}', '\n}')
    return {"config": json.loads(global_),
            "peers": json.loads(peers_),
            "bindings": json.loads(bindings_)}


def serialize(sxpd_, odl_, path):
    file_name = './' + os.path.basename(__file__)
    if path == file_name:
        lines = []
        with open(path, "r") as f:
            for line in f:
                lines += line
                if '''if __name__ == '__main__':\n''' in line:
                    break
        with open(path, "w") as f:
            f.writelines(lines)
            append_data(sxpd_, odl_, f)
    else:
        with open(path, "w") as f:
            with open('./' + os.path.basename(__file__), 'r') as s:
                for line in s:
                    f.write(line)
                    if '''if __name__ == '__main__':\n''' in line:
                        break
            append_data(sxpd_, odl_, f)


def append_data(sxpd_, odl_, f):
    # SXPD settings
    f.write('    sxpd_ = \'\'\'')
    f.write(pickle.dumps(sxpd_, 0).decode('utf-8'))
    f.write('\'\'\'\n')
    # ODL setting
    f.write('\n    odl_ = \'\'\'')
    f.write(pickle.dumps(odl_, 0).decode('utf-8'))
    f.write('\'\'\'\n')
    f.write('''    sxpd = pickle.loads(sxpd_.encode('utf-8'))\n''')
    f.write('''    odl = pickle.loads(odl_.encode('utf-8'))\n''')
    f.write('''    sxpd_main_handler()\n''')
    f.write('''    serialize(sxpd, odl, './node_' + str(sxpd.get_id()) + '.py')\n''')


def sxpd_main_handler():
    global verbosity
    parser = argparse.ArgumentParser(description='SXPD script for controlling and storing config data.')
    parser.add_argument('action', type=str,
                        choices=['start', 'stop', 'refresh', 'status', 'master-db', 'connection-status', 'add', 'del',
                                 'export'],
                        help='start - start sxpdprocess, stop - kill sxpd process, ' +
                             'refresh - update config in sxpd process, status - show status od sxpd, ' +
                             'export - export current config to file, ' + 'add/remove - update bindings or connections')
    parser.add_argument('-v', action='store_true', help='Enable verbose mode.')
    parser.add_argument('--no_odl', action='store_true', help='Do not add connections to ODL.')
    # NODE bindings
    parser.add_argument('--bindings', type=str, nargs='+',
                        help='Adds local bindings to sxpd. Syntax: [SGT,IP_PREFIX] [SGT,IP_PREFIX] ... ')
    # NODE connections
    parser.add_argument('--connections', type=str, nargs='+',
                        help='Adds connections to sxpd.' +
                             ' Syntax [MODE,IP] [MODE,IP:PORT] [MODE,IP,VERSION] [MODE,IP,VERSION,PASSWORD] ...')
    argcomplete.autocomplete(parser)
    args = parser.parse_args()
    verbosity = args.v
    if args.action == 'add' or args.action == 'del':
        if args.bindings is not None:
            for binding in args.bindings:
                if args.action == 'add':
                    sxpd.add_binding(binding.split(',')[0], binding.split(',')[1])
                else:
                    sxpd.remove_binding(binding.split(',')[0], binding.split(',')[1])
        if args.connections is not None:
            for connection in args.connections:
                params = connection.split(',')
                if len(params) == 2 or len(params) == 3:
                    if args.action == 'add':
                        sxpd.add_connection(get_reverse_connection_mode(params[0]), params[1])
                    else:
                        sxpd.remove_connection(get_reverse_connection_mode(params[0]), params[1])
                elif len(params) == 4:
                    if args.action == 'add':
                        sxpd.add_connection(get_reverse_connection_mode(params[0]), params[1], params[3])
                    else:
                        sxpd.remove_connection(get_reverse_connection_mode(params[0]), params[1], params[3])
                # TODO check on port too
                if odl.get_ip() == params[1].split(':')[0]:
                    if args.action == 'add':
                        odl.add_connection(peer_address=sxpd.get_ip(), tcp_port=sxpd.get_port(),
                                           password=sxpd.get_password() if len(params) < 4 else params[3],
                                           mode=get_reverse_connection_mode(params[0]),
                                           version_=parse_version(4 if len(params) < 3 else params[2]))
                    else:
                        odl.remove_connection(peer_address=sxpd.get_ip(), tcp_port=sxpd.get_port())
        sxpd.update_deamon()
        sxpd.export('/tmp/node_' + str(sxpd.get_id()) + '.cfg')
        sxpd.update_deamon()
    elif args.action == 'start':
        sxpd.start_deamon(None if args.no_odl else odl)
    elif args.action == 'stop':
        sxpd.stop_deamon(None if args.no_odl else odl)
    elif args.action == 'refresh':
        sxpd.update_deamon()
    elif args.action == 'status':
        sxpd.status()
        odl.status()
    elif args.action == 'master-db':
        sxpd.master_database()
    elif args.action == 'connection-status':
        sxpd.connection_status()
    elif args.action == 'export':
        sxpd.export()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Script generating configuration for sxpd client')
    # Script mode
    parser.add_argument('-c', action='store_true', help='Generate config file for sxpd daemon.')
    parser.add_argument('-d', action='store_true', help='Create python script for managing sxpd daemon.')
    # NODE settings
    parser.add_argument('id', type=int, help='ID that will be propagated to remote peers.')
    parser.add_argument('--ip', type=str, default='127.0.0.1',
                        help='Ip on which sxpd will listen for incoming connections.')
    parser.add_argument('--port', type=int, default=64999,
                        help='Port on which sxpd will listen for incoming connections.')
    parser.add_argument('--password', type=str, default='none', help='Global password used in TCP-MD5 hand-shake.')
    # ODL settings
    parser.add_argument('--odl_ip', type=str, default='127.0.0.1', help='Ip of remote SXP-ODL node.')
    parser.add_argument('--odl_id', type=str, default='127.0.0.1', help='Id of remote SXP-ODL node.')
    parser.add_argument('--odl_port', type=int, default=64999, help='Port of remote SXP-ODL node.')
    # NODE bindings
    parser.add_argument('--bindings', type=str, nargs='+',
                        help='Adds local bindings to sxpd. Syntax: [SGT,IP_PREFIX] [SGT,IP_PREFIX] ... ')
    # NODE connections
    parser.add_argument('--connections', type=str, nargs='+',
                        help='Adds connections to sxpd.' +
                             ' Syntax [MODE,IP] [MODE,IP:PORT] [MODE,IP,VERSION] [MODE,IP,VERSION,PASSWORD] ...')
    # Config
    parser.add_argument('--config', type=argparse.FileType('r'), help='Use already created sxpd config to run daemon.')
    argcomplete.autocomplete(parser)
    args = parser.parse_args()

    odl = ODL(args.odl_ip, args.port, args.odl_id)
    sxpd = SXPD(args.ip, args.id, initializer=import_config(args.config), port=args.port, passowrd=args.password)
    if args.bindings is not None:
        for binding in args.bindings:
            sxpd.add_binding(binding.split(',')[0], binding.split(',')[1])
    if args.connections is not None:
        for connection in args.connections:
            params = connection.split(',')
            if len(params) == 2 or len(params) == 3:
                sxpd.add_connection(get_reverse_connection_mode(params[0]), params[1])
            elif len(params) == 4:
                sxpd.add_connection(get_reverse_connection_mode(params[0]), params[1], params[3])
    # Exclusive group maybe
    if args.c:
        sxpd.export()
    if args.d:
        serialize(sxpd, odl, './node_' + str(sxpd.get_id()) + '.py')
