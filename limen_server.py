#!/usr/bin/python3

"""
This is the server side script that will receive the bare arguments from a
client and add new vaults, add new records, or get previously stored records.
Each connection should send data like so:
    is_new_vault;record_name`record_value`is_delete;raw_key;vault_name

is_new_vault :  denotes if the user would like to create a new vault
record_name  :  the record name the user would like to access from the vault
record_value :  if supplied, it will add the record to the vault
is_delete    :  can be either '0' or '1'
                denotes if the user would like to read record or delete the record/vault
raw_key      :  the password to the vault for authentication
vault_name   :  the vault to be accessed

NOTE: raw password transmission is not ideal but should be secure since we are
      communicating over SSL.

(c) Conrad Heidebrecht    ver. 0.5.0 beta    07/08/2017
"""

import hashlib
import math
import os
import socket
import time
from sys import argv, byteorder

from AESCipher import AESCipher


##----GLOBAL VARIABLES----##

# configuration
MAINDIR = "/etc/limen/"
STOREDIR = "vaults/"
CONFNAME = "limen.conf"
LOGNAME = "limen_serv.log"

# salt generation
CHARCHOICES = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@\#$%^&*()-_+=[]{}~`\\<>.?/|"
# salt len
MINSALT = 8
MAXSALT = 32
# salt bytes of entropy
ENTROPYLEN = 4
ENTROPYCHAR = 2

# server connections configuration
default_port = 626
default_max_conns = 1


##----HELPER FUNCTIONS----##

# usage to show arguments
def usage ():
    print("""

        ./limen_server.py [-p listen_port] [-m maximum_connections]

        -p  |  port : specify the port to listen on (default is 626)
        -m  |  maximum concurrent connections : the maximum number of machines that
               can connect to the service at the same time (default is 1)

        """)

    quit()


# check that this is run in root
def check_permissions ():
    return 0 == os.getuid()


# write to log any issues that happen
def write_log (string, is_input_err=True, sock=None, logfile=MAINDIR+LOGNAME):
    if not is_input_err:
        to_log = str(int(time.time())) + " - " + string
    else:
        to_log = str(int(time.time())) + " - [!!] " + string
        send_data(sock, to_log)

    if not write_file(logfile, to_log, "w+"):
        os.system("mkdir -p %s; touch %s" % ('/'.join(logfile.split('/')[:-1]), logfile))


# basic file reading
def read_file (filename):
    contents = ""
    with open(filename, 'r') as fname:
        for line in fname:
            contents += line.strip()

    return contents


# basic file writing
def write_file (filename, data, mode='w'):
    try:
        with open(filename, mode) as fname:
            fname.writelines(data)
    except FileNotFoundError:
        return False

    return True


# send data over socket
def send_data (sock, data, attempts=3):
    for i in range(attempts):
        try:
            sock.send(data.encode("utf-8"))
            return
        except:
            pass
    write_log("An internal error occurred.", is_input_err=False)


# receive data over socket
def recv_data (sock):
    data = ""
    while True:
        tmp = sock.recv(4096)
        data += tmp.decode("utf-8")
        if len(tmp) < 4096:
            break

    return data


# hashing function with a salt and sha512
def hash_key (raw_key, salt=""):
    if not salt:
        # take a random number and map it (MINSALT to MAXSALT)
        # (random * newrange / oldrange) + min
        salt_len = math.floor(((int.from_bytes(os.urandom(ENTROPYLEN), byteorder=byteorder) * (MAXSALT - MINSALT)) / (2 ** (ENTROPYLEN * 8))) + MINSALT)
        # generate the salt from CHARCHOICES
        for _ in range(int(salt_len)):
            salt += CHARCHOICES[int(math.floor((int.from_bytes(os.urandom(ENTROPYCHAR), byteorder=byteorder) * len(CHARCHOICES)) / (2 ** (ENTROPYCHAR * 8))))]

    # return the hash and the salt used
    return [hashlib.sha512((raw_key + salt).encode("utf-8")).hexdigest(), salt]


# configuration retrieving function
def get_config (directory=MAINDIR, conffile=CONFNAME):
    config = {}
    # try to retrieve and parse the configuration
    try:
        data = read_file(directory + conffile).split(';')
        for d in data:
            config[d.split(":")[0].strip()] = [i.strip() for i in d.split(":")[1].split(',')]
    # if they are not created then make the directory and configuration file
    except FileNotFoundError:
        os.system("mkdir -p %s; touch %s" % (directory, directory + conffile))
    # if configuration is empty then handle it
    except IndexError:
        pass

    # if there is no configuration, return the dict with empty values
    if not len(config):
        config = { "vaults": [], "keys": [], "salts": [] }

    return config


# configuration writing function
def update_config (config, directory=MAINDIR, conffile=CONFNAME):
    str_config = []
    for key in config.keys():
        str_config.append(key+':'+','.join(config[key]))
    write_file(directory+conffile, ';'.join(str_config), 'w')


# create a vault
def create_vault (raw_key, vault_name, cur_config, directory=MAINDIR+STOREDIR):
    os.system("mkdir -p %s; touch %s" % (directory, directory+vault_name))
    write_file(directory+vault_name, "", "w+")
    cur_config["vaults"].append(vault_name)
    [hashed, salt] = hash_key(raw_key)
    cur_config["keys"].append(hashed)
    cur_config["salts"].append(salt)


# for adding a record to a vault
# record info is : [record_name, record_value]
def add_record (record_info, vault, encrypter, directory=MAINDIR+STOREDIR):
    print(record_info)
    # strip of the end characters from the data it was sent surrounded with '`'
    to_save = encrypter.encrypt(record_info[1][:-1]).decode("utf-8")
    print(record_info[0]+':'+to_save+';')
    write_file(directory+vault, record_info[0]+':'+to_save+';', "w+")


# for getting a record from a vault
def get_record (record_name, vault, encrypter, directory=MAINDIR+STOREDIR):
    vault_content = {}
    for record in read_file(directory+vault).split(';'):
        print(record)
        if record:
            vault_content[record.split(':')[0]] = record.split(':')[1]
        if record_name in vault_content.keys():
            return encrypter.decrypt(vault_content[record_name].encode("utf-8"))
        else:
            write_log("Record not found in desired vault!")
            return "Record not found in desired vault!"


def del_record (name, vault, directory=MAINDIR+STOREDIR, cur_config=None):
    if not name and cur_config:
        os.system("rm -rf %s" % (directory+name))
        index = cur_config["vaults"].index(name)
        del cur_config["vaults"][index]
        del cur_config["keys"][index]
        del cur_config["salts"][index]
    elif name and not cur_config:
        records = read_file(directory+vault).split(';')
        for r, record in enumerate(records):
            if record and name == record.split(':')[0]:
                del records[r]
                return write_file(directory+vault, records)
    else:
        raise ValueError


# get commandline arguments
def parse_args ():
    # returns args = [port_to_listen_on, max_connections]
    args = [0 for _ in range(2)]
    try:
        for i, arg in enumerate(argv[1:]):
            if arg == "-h" or arg == "--help":
                usage()
            if arg == "-p":
                args[0] = int(argv[i+1].strip())
            elif arg == "-m":
                args[1] = int(arv[i+1].strip())
    except IndexError:
        usage()
    except ValueError:
        usage()

    return args


# handle the client
def handle_request (sock):
    # receive data (format is:
    # is_new_vault;record_name`record_value`is_delete;raw_key;vault_name)
    args = recv_data(sock).strip().split(';')
    # first get the current configuration
    config = get_config()
    # first check if we want a new vault
    if int(args[0]):
        create_vault(args[2], args[3], config)
        update_config(config)
        return "Vault created successfully!"
    # if not then check the password is correct
    index = config["vaults"].index(args[3])
    if hash_key(args[2], config["salts"][index])[0] != config["keys"][index]:
        return "Invalid password!"
    # if the length of the second argument is > 1 then it is adding a record
    encrypter = AESCipher(args[2] + config["salts"][index])
    if len(args[1].strip().split('`')) > 2:
        add_record(args[1].strip().split('`')[1], args[3], encrypter)
        return "Updated '" + args[1].strip().split('`', 1)[0] + "' successfully!"
    elif args[1].strip()[-1] == '0':
        return "The value stored in '" + args[1].strip()[:-1] + "' is :  " \
                + get_record(args[1].strip()[:-1], args[3], encrypter)
    elif args[1].strip()[-1] == '1':
        del_record(args[1].strip().split(' ')[0], False) if [1].strip().split(' ')[0] != '1' else del_record(args[3], True)
        return (args[1].strip().split(' ')[0] if args[1].strip().split(' ')[0] != '1' else args[3]) + "has been removed."

    return False


##----MAIN SCRIPT STARTS HERE----##

def main ():
    # check proper permissions
    if not check_permissions():
        print("Must be run with root permissions!")
        return
    # get commandline arguments
    cmdargs = parse_args()
    port, max_conns = cmdargs[0] if cmdargs[0] else default_port, cmdargs[1] if cmdargs[1] else default_max_conns

    # initialize server
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", port))
    server.listen(max_conns)
    write_log("[**] Started listening on %s:%d." % ("0.0.0.0", port))

    # main loop
    while True:
        try:
            # accept connections
            client, addr = server.accept()
            write_log("[**] Accepted request from %s:%d." % (addr[0], addr[1]))
            to_send = handle_request(client)
            send_data(client,to_send if to_send else "Failed to update vault!")
            client.close()
        except KeyboardInterrupt:
            write_log("[**] Shutting down cleanly.")
            return


if __name__ == "__main__":
    main()


