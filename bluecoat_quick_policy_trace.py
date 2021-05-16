import sys,socket
import paramiko
import time
import requests
import argparse, csv, dbops
import base64
import os, threading
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


colormap = {
    "red": "\033[91m",
    "yellow": "\033[93m",
    "green": "\033[92m",
    "blue": "\033[1;36m",
    "reset": "\033[0m"
}

def red(text):
    """
    Description:
        Return text in red color.
    """
    return colormap["red"] + text + colormap["reset"]

def yellow(text):
    """
    Description:
        Return text in yellow color.
    """
    return colormap["yellow"] + text + colormap["reset"]

def green(text):
    """
    Description:
        Return text in green color.
    """
    return colormap["green"] + text + colormap["reset"]

def blue(text):
    """
    Description:
        Return text in blue color.
    """
    return colormap["blue"] + text + colormap["reset"]

def introText():
    print("")
    print("")
    print(blue("#########################################"))
    print(green("######  BlueCoat Symantec Broadcom ######"))
    print(green("## ProxySG Quick Policy Trace Tool v1.1 ##"))
    print(blue("#########################################"))
    print(green("Talha Koc ## https://github.com/koctalha"))
    print("")
    print("")
    if traceisActive == 1:
        print(yellow("Trace has opened previously. Program will deactivate it and download the generated file."))

def writeCreds(pin,username,password,enablePassword):
    pin = pin.encode('utf-8')
    username = username.encode('utf-8')
    password = password.encode('utf-8')
    enablePassword = enablePassword.encode('utf-8')
    salt = b'\x0e\xea\xed\\z\x9ex\xb0\xf2\xccj\xf2\x18\xe2\xb7:'
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=100000)
    key = base64.urlsafe_b64encode(kdf.derive(pin))
    f = Fernet(key)
    usernameEnc = f.encrypt(username)
    passwordEnc = f.encrypt(password)
    enablePasswordEnc = f.encrypt(enablePassword)
    dbops.dbwKey(key.decode('utf-8'))
    dbops.dbwUsername(usernameEnc.decode('utf-8'))
    dbops.dbwPassword(passwordEnc.decode('utf-8'))
    dbops.dbwEnablePassword(enablePasswordEnc.decode('utf-8'))

def pinCheck(pin):
    pin = pin.encode('utf-8')
    salt = b'\x0e\xea\xed\\z\x9ex\xb0\xf2\xccj\xf2\x18\xe2\xb7:'
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=100000)
    key = base64.urlsafe_b64encode(kdf.derive(pin))
    key = key.decode('utf-8')
    isKey = dbops.dbrKey()

    if key == isKey:
        #print("Pincode is true!")
        return True
    else:
        #print("Pincode is wrong!")
        return False

def readCreds(x):
    key = dbops.dbrKey().encode('utf-8')
    f = Fernet(key)
    dbEnc = x.encode('utf-8')
    dbDec=f.decrypt(dbEnc)
    dbDec = dbDec.decode('utf-8')
    return dbDec

def checkPyVersion():# Check python version
    if sys.version_info[0] < 3:
        sys.exit(red("Upgrade Python Version"))
    else:
        green("Program Initializing...")

def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False

    return True

class ssh:
    shell = None
    client = None
    transport = None
    readflag = 0
 
    def __init__(self, address, username, password):
        print("Connecting to server on ip", str(address) + ".")
        self.client = paramiko.client.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.client.AutoAddPolicy())
        self.client.connect(address, username=username, password=password, look_for_keys=False)
        self.transport = paramiko.Transport((address, 22))
        self.transport.connect(username=username, password=password)
 
        thread = threading.Thread(target=self.process)
        thread.daemon = True
        thread.start()
 
    def closeConnection(self):
        if(self.client != None):
            self.client.close()
            self.transport.close()
 
    def openShell(self):
        self.shell = self.client.invoke_shell()
 
    def sendShell(self, command):
        if(self.shell):
            self.shell.send(command + "\n")
            readflag = 1
            if self.shell != None and self.shell.recv_ready():
                alldata = self.shell.recv(1024)
                while self.shell.recv_ready():
                    alldata += self.shell.recv(1024)
                strdata = str(alldata, "utf8")
                strdata.replace('\r', '')
                print(strdata, end = "")
                if(strdata.endswith("$ ")):
                    print("\n$ ", end = "")

        else:
            print("Shell not opened.")
            readflag = 0

    def sendcplShell(self, command):
        if(self.shell):
            self.shell.send(command)
            readflag = 1
            if self.shell != None and self.shell.recv_ready():
                alldata = self.shell.recv(1024)
                while self.shell.recv_ready():
                    alldata += self.shell.recv(1024)
                strdata = str(alldata, "utf8")
                strdata.replace('\r', '')
                print(strdata, end = "")
                if(strdata.endswith("$ ")):
                    print("\n$ ", end = "")

        else:
            print("Shell not opened.")
            readflag = 0
 
 
    def process(self):
        global connection
        while True:
            # Print data when available
            if self.shell != None and self.shell.recv_ready():
                alldata = self.shell.recv(1024)
                while self.shell.recv_ready():
                    alldata += self.shell.recv(1024)
                strdata = str(alldata, "utf8")
                strdata.replace('\r', '')
                print(strdata, end = "")
                if(strdata.endswith("$ ")):
                    print("\n$ ", end = "")

def localPolicyDownload(proxyIP,proxyUser,proxyPW):  # ProxySG Local Policy Download #start
    proxyURL = "https://"+proxyIP+":8082/local_policy_source.txt"
    localPolicyText = requests.get(proxyURL,verify=False, auth=(proxyUser, proxyPW))
    policyFile = open('rawLocalPolicy.txt', 'w')
    policyFile.write(localPolicyText.text)
    policyFile.close()

def traceDownload(proxyIP,proxyUser,proxyPW):  # ProxySG Local Policy Download #start
    proxyURL = "https://"+proxyIP+":8082/Policy/Trace/auto-generated-trace.txt"
    traceText = requests.get(proxyURL,verify=False, auth=(proxyUser, proxyPW))
    traceFileName = "traceFile"+timestr+".txt"
    policyFile = open(traceFileName, 'w')
    policyFile.write(traceText.text)
    policyFile.close()

def sshPolicyDeploy(sshServer,sshUsername,sshPassword,enablePassword,traceisActive):
 
    connection = ssh(sshServer, sshUsername, sshPassword)
    connection.openShell()
    closeFlag = 0

    while closeFlag == 0:
        connection.sendShell("enable")
        time.sleep(1)
        connection.sendShell(enablePassword)
        time.sleep(1)
        connection.sendShell("configure terminal")
        time.sleep(1)
        if traceisActive == 0: #Delete old traces on Proxy
            connection.sendShell("show advanced-url /Policy/Delete-All-Traces")
            time.sleep(2)
        connection.sendShell("inline policy local end-of-file")
        time.sleep(1)
        if traceisActive == 0:
            traceCommand = ";trace command starts\n<Proxy>\nclient.address="+clientIP+" trace.request(yes) trace.rules(all) trace.destination(\"auto-generated-trace.txt\")\n;trace command ends"
            connection.sendShell(traceCommand)
            time.sleep(1)
        policyFile = open('rawLocalPolicy.txt', 'r')
        time.sleep(2)
        connection.sendcplShell(policyFile.read())
        time.sleep(2)
        print("")
        connection.sendcplShell("end-of-file")
        print("")
        closeFlag = 1

    connection.closeConnection()

####### Main Flow ###############################################################

# arguments configuration
descText = 'This is a test program. It demonstrates how to use the argparse module with a program description.'
parser = argparse.ArgumentParser(description=descText)
parser.add_argument("--pincode","-pin",help="Enter pincode to store credentials.")
parser.add_argument("--proxy","-p",help="Enter proxy IP. Make sure it isn't pool IP.")
parser.add_argument("--client","-c",help="Enter client IP that you want to trace.")
parser.add_argument("--username","-u",help="Enter username for SSH connection.")
parser.add_argument("--password","-pw",help="Enter password between 'examplePW'.")
parser.add_argument("--enablePassword","-e",help="Enter enable password between 'examplePW'.")
args=parser.parse_args()

#global variables start
timestr = time.strftime("-%Y%m%d-%H%M%S")
traceisActive = int(dbops.dbrTraceActive())

#intro starts
introText()
checkPyVersion()

#check arguments
if args.proxy:
    proxyIP = args.proxy
    isValid = is_valid_ipv4_address(proxyIP)
    while isValid is False:
        proxyIP = input("Enter valid Proxy IP: ")
        isValid = is_valid_ipv4_address(proxyIP)

    print("Proxy IP: ",proxyIP)

else:
    print(red("Please, check your parameters and initialize the program again. For detailed information use --help or -h."))
    print("")
    print("")
    print("")
    time.sleep(1)
    exit()

if args.client:
    clientIP = args.client
    isValid = is_valid_ipv4_address(clientIP)
    while isValid is False:
        clientIP = input("Enter valid Client IP: ")
        isValid = is_valid_ipv4_address(clientIP)
    print("Client IP: ",args.client)
elif traceisActive == 0:
    print(red("Please, check your parameters and initialize the program again. For detailed information use --help or -h."))
    print("")
    print("")
    print("")
    time.sleep(1)
    exit() 

#validate pincode 
if args.pincode:
    if args.username and args.password and args.enablePassword: #New credentials write
        writeCreds(args.pincode,args.username,args.password,args.enablePassword)
        usernameDec = args.username
        passwordDec = args.password
        enablePasswordDec = args.enablePassword
    else:
        if pinCheck(args.pincode) is True:
            print("")
            print("")
            print(green("Pincode is true! Your stored credentials is going to be used."))
            print("")
            print("")
            usernameDec = readCreds(dbops.dbrUsername())
            passwordDec = readCreds(dbops.dbrPassword())
            enablePasswordDec = readCreds(dbops.dbrEnablePassword())
        else:
            print(red("Wrong pincode. Please try again!"))
            print("")
            print("")
            print("")
            time.sleep(1)
            exit()
    ##### SSH Operations Start Here 
    if traceisActive == 0:
        localPolicyDownload(proxyIP,usernameDec,passwordDec)
        print("")
        print(blue("Trace policy is going to be applied."))
        print("")
        sshPolicyDeploy(proxyIP,usernameDec,passwordDec,passwordDec,traceisActive)
        print("")
        print(green("ProxySG policy trace is active!"))
        print("")

    if traceisActive == 1:
        sshPolicyDeploy(proxyIP,usernameDec,passwordDec,passwordDec,traceisActive)
        print("")
        print(green("Trace file is generated and downloaded."))
        print("")
        traceDownload(proxyIP,usernameDec,passwordDec)
    
    traceisActive = int(not(traceisActive)) #reverse trace flag here
    dbops.dbwTraceActive(traceisActive) #reverse trace flag here

else:
    print(red("Please, check your parameters and initialize the program again. For detailed information use --help or -h."))
    print("")
    print("")
    print("")
    time.sleep(1)
    exit()