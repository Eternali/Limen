#!/usr/bin/python3

"""
This is the client side script that receives arguments and queries the server
accordingly to retrieve or add data to the specified vaults.
Each connection should send data like so: 
    is_new_vault;record_name record_value;raw_key;vault_name;is_delete

is_new_vault :  denotes if the user would like to create a new vault
record_name  :  the record name the user would like to access from the vault
record_value :  if supplied, it will add the record to the vault
raw_key      :  the password to the vault for authentication
vault_name   :  the vault to be accessed

NOTE: raw password transmission is not ideal but should be secure since we are
      communicating over SSL.

(c) Conrad Heidebrecht    ver. 0.5.0 Beta    07/08/2017
"""

import getpass
import os
import socket
import time
from sys import argv


##----GLOBAL VARIABLES----##

# configuration
MAINDIR = "/etc/limen/"
LOGNAME = "limen.log"

# server setup configuration
server_port = 626
server_ip = ""


## custom exception classes
class PermissionError (Exception):
    """This """


##----HELPER FUNCTIONS----##

# usage to show arguments
def usage ():
    print("""

        ./limen_client.py [-n] [-s record_name record_value record_type,
             -g record_name, -d record_name] [-p port] [-h server_ip] vault_name

        -n   |  New: Start a new vault stored in the specified vault_name
                     NOTE: You must create a vault before adding any records
        -s   |  Set: Add a new encrypted record or update an old one (record_name) with the value 
                     (record_value) of type (record_type) 'string' or 'file'
        -g   |  Get: Retrieve a record (record_name) from a vault (vault_name)
        -d   |  Delete: Delete a record (record_name) from a vault (vault_name)
                        If record_name is left blank, the entire vault will be deleted.
        -p   |  Server port to connect to (default is 626)
        -h   |  Server hostname or IP address to connect to

        """)

    quit()


# check that this is run in root
def check_permissions ():
    return 0 == os.getuid()


# write to log activity
def write_log (string, logfile=MAINDIR+LOGNAME):
    to_log = str(int(time.time())) + " - " + string
    
    if not write_file(logfile, to_log, "w+"):
        os.system("mkdir -p %s; touch %s" % ('/'.join(logfile.split('/')[:-1]), logfile))


# basic file writing
def write_file (filename, data, mode='w'):
    try:
        with open(filename, mode) as fname:
            fname.writelines(data)
    except FileNotFoundError:
        return False

    return True


# basic file reading
def read_file (filename, mode='r'):
    contents = ""
    with open(filename, mode) as fname:
        for line in fname:
            data += line.strip()

    return contents


# send data over socket
def send_data (sock, data, attempts=3):
    for i in range(attempts):
        try:
            sock.send(data.encode("utf-8"))
            write_log("Sent %s to server." % data)
            return
        except:
            pass
    write_log("[!!] Failed to send data!")


# receive data over socket
def recv_data (sock):
    data = ""
    while True:
        tmp = sock.recv(4096)
        data += tmp.decode("utf-8")
        if len(tmp) < 4096:
            break

    write_log("Received: %s" % data)
    return data


# get commandline arguments
def parse_args ():
    # returns args = [is_new, "[record_name [record_value record_type]] is_delete" else 0,
    #                 vault_name, port else 0, server_ip]
    args = [0 for _ in range(5)]

    try:
        for arg in range(1, len(argv)):
            if argv[arg] == "-n":
                args[0] = 1
            elif argv[arg] == "-s":
                to_encrypt = read_file(argv[arg+2]) if "file" in argv[arg+3].lower() else argv[arg+2]
                args[1] = argv[arg+1].strip() + '`'+to_encrypt+'`' + '0'
            elif argv[arg] == "-g":
                args[1] = argv[arg+1].strip() + '0'
            elif argv[arg] == "-d":
                args[1] = (argv[arg+1].strip() if arg[arg+1].strip()[0] != '-' else '') + '1'
            elif argv[arg] == "-p":
                args[3] = argv[arg+1].strip()
            elif argv[arg] == "-h":
                args[4] = argv[arg+1].strip()
        args[2] = argv[-1].strip()
    except Exception:
            usage()

    if args[2] == 0 or args[4] == 0:
        print("[!!] Neither vault_name or server_ip can be empty.")
        usage()
    return args


##----MAIN STARTS HERE----##

def main ():
    # parse arguments and get password
    args = parse_args()
    raw_key = getpass.getpass()
    args.insert(2, raw_key)

    # initialize socket and connect to server
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        conn.connect((args[5], args[4] if args[4] else server_port))
        write_log("[**] Connected to %s:%s." % (args[5], args[4] if args[4] else server_port))
        send_data(conn, ';'.join([str(a) for a in args[:4]]))
        response = recv_data(conn)
    except Exception:
        write_log("[!!] Failed to connect to %s:%s." % (args[5], args[4] if args[4] else server_port))
        response = "[!!] Failed to connect to server!"

    print(response)


if __name__ == "__main__":
    main()


