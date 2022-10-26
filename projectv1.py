from scapy.all import *
import socket
from Crypto.Cipher import AES as AS
import hashlib
#from cryptography.fernet import Fernet

'''
created by ilanit elsa

'''

'''
PART 1

Three way handshake
'''
#This fuction we try to implement a tcp connection with an ip,port and send a payload
def tcp_flow(targe_ip,target_port,msg):
    #variables
    is_succssed = False
    ip = IP(dst=targe_ip)
    #Step 1 : send syn request
    #First we will check if the target host is alive and if destination port is open by sending syn packet with a syn request
    syn_request = ip/TCP(dport=int(target_port))
    # Send the packet and get answers and answers
    ans,unans = sr(syn_request,timeout=1)
    #Checking if we receive an answer
    if not ans:
        #If we don't get an answer we will send feedback
        return is_succssed,f'Host {target_port} is offline'
    else:
        # Step 2 find syn_ack response
        #We receved a list as a response and we need to look for the syn flag
        for snd,rcv in ans:
            if rcv[TCP].flags == 'SA':
                #Step 3 send an ack request
                # To finsh the three hadeshake we will send an ack request
               ack_request = ip/TCP(dport=int(target_port),flags='A',seq=rcv.seq+1,ack=snd.seq+1)/Raw(load=msg)
               ack_request.show()
               send(ack_request)
               is_succssed = True
               msg = (ack_request[Raw].load).decode('utf-8')
            else:
                msg = None
                print(f'Host is alive but {target_port} is close')

    return is_succssed,msg

#f,a = tcp_flow('140.82.112.4',80,'hjhj')
#print(f,a)

'''
PART 2
Port scanner and banner
'''
# This function will find the open ports to one ip address and return a list of that open ports
#determine whether `host` has the `port` open
def scanner(target_ip,port_list):
    open_Ports = []
    for port in port_list:
        # print(type(port))
        # creates a new socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        # tries to connect to host using that port(don't need try/except because we use connect_ex)
        result = s.connect_ex((target_ip, int(port)))
        # The result is a response we get from try to connect (it is a number)
        if result == 0:
            # the connection was established, port is open,add the port to list
            open_Ports.append(port)
            s.close()
        else:
            # cannot connect, port is closed ,close the sokete and contiue to the next port on the list
            s.close()
            continue
    return open_Ports

# In this function we want to get information about the target like the service/version of the port that is open / os
def banner_grabber(ip, ports):

    ls_banner = []
    for port in ports:
        # creates a new socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #s.settimeout(2)
        # tries to connect to host
        s.connect((ip,int(port)))
        banner = s.recv(1024)

        if not banner:
        #print(type(banner))
        #print(banner + 'test1')
            ls_banner.append(('unkown', port))
            s.close()

        else:
            ls_banner.append((banner.decode(), port))
            s.close()
    return ls_banner

def combine():
    ls_ports = [443,22,53,101,80,95]
    ls_tup = []
    ip = '140.82.112.4'

    ls_ports_op=scanner(ip,ls_ports)
    #print(ls_ports)
    ls_tup =banner_grabber('140.82.112.4',ls_ports_op)
   # print(ls_tup)
    for k,v in ls_tup:
        print(f'IP address - {ip}\n')
        print(f'Port {v}\t\t\t\t {k}')

combine()
'''
PART 3
Encryption and decryption using ASE algorithm
ASE 
'''
#This function will genarat a key to encrypt and decrypt
def genarating_key():
    # The lenght of the password impact the key--> longger password is better
    # We need to encode it to make it to bytes
    my_secret = 'brownskingirl'.encode()
    # standart lenght key is 16/24/32
    # use hash to get the correct lenght of the key
    key = hashlib.sha3_256(my_secret).digest()
    # create the mode --> block chipher mode
    mode = AS.MODE_CBC
    # vector need to be 16b --> help to randomize the ciphertxt
    IV = "This is an IV256".encode()
    cipher = AS.new(key, mode, IV)
    return cipher

# This function will encrypt a mssagee to ciphertext
def encrypt(msg):
    cipher = genarating_key()
    cnt = 0
    org_msg = msg
    #The msg need to 16b so we will add a padding to her if it is not 16b
    while len(msg) % 16 != 0:
        msg = msg + " "
    encrypted_msg = cipher.encrypt(msg.encode())
    return encrypted_msg

# Decrypt to plaintext
def decrypt(enc_str):
    cipher = genarating_key()
    print(enc_str)
    decrypt_msg = cipher.decrypt(enc_str)

    return decrypt_msg.decode()

# In this function we encrypt the paylod and send it to tcp_flow function
def send_encrypted_message(ip,port,msg):
    enc_msg=encrypt(msg)
    tcp_flow(ip,port,enc_msg)







