import ssl
import socket
import OpenSSL.crypto as crypto
import os
from datetime import datetime, timedelta
from flask import Flask, request, render_template

 
app = Flask(__name__)
#import Crypto.Util
hostname = ''
port = 443
file_name = 'hosts.txt'

current_dir = os.getcwd()
download_dir = 'certs'
download_certs = 1


def get_hosts(file_name):

    hosts = {}
    with open(file_name, 'r') as f:
        for line in f:
            if not line.startswith('#'):
                host_data = line.split()
                hosts.update({host_data[0]: host_data[1] if len(host_data) == 2 else port})
    return hosts


def get_date(str_dt):
    #dt_format = r'%b %d %H:%M:%S'
    dt_format = '%Y%m%d%H%M%S'
    str_dt = str_dt.decode('UTF-8')
    str_dt = str_dt[:-1]
    return datetime.strptime(str_dt, dt_format)

def get_date_v2(str_dt):
    #Oct 20 12: 11: 11 2020 GMT'
    dt_format = '%b %d %H:%M:%S GMT'
    return datetime.strptime(str_dt, dt_format)

def get_host_info(hostname, port=port):
    #print(hostname, port)
    level = ''
    not_before = None
    not_after = None
    delta = ' - '
    expired = None
    issuer = None
    subject = None
    info = ''

    try:
        cert_pem = ssl.get_server_certificate((hostname, port))
        cert_der = ssl.PEM_cert_to_DER_cert(cert_pem)
        cert_x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
        not_after_str = cert_x509.get_notAfter()
        not_after = get_date(not_after_str)
        not_before_str = cert_x509.get_notBefore()
        not_before = get_date(not_before_str)
        issuer = cert_x509.get_issuer().CN
        subject = cert_x509.get_subject().CN
        #print(subject)
        is_expired = cert_x509.has_expired()



        #print([na.value for na in cert_pem.subject if na.oid._dotted_string == "2.5.4.3"][0])
       #   f'hostname {hostname}, port {port}, issuer {issuer}, subject {subject}')

        delta = not_after - datetime.now()
        if not_after <= datetime.now():
            expired = True
        else:
            expired = False
        #скачать сертификат
        if download_certs == 1:
            cert_download(cert_der, hostname)

        #установка уровня
        if expired == True:
            level = 'achtung'
        
        if delta.days >=2:
            level = 'normal'

        if 0 <= delta.days < 2:
            level = 'warning'

    except ConnectionRefusedError:
        
        info = 'Нет подключения к узлу'
        level = 'achtung'
        #pass
        #return {'delta': '-', 'host': hostname, 'not_after': None, 'not_before': None, 'expired': None, 'level': level}
    
    except ssl.SSLError as err:
        info = 'Возможно, сертификат отсутствует'
        level = 'achtung'
        #return {'delta': '-', 'host': hostname, 'not_after': None, 'not_before': None, 'expired': 'возможно, сертификата нет', 'level': level}
    
    except TimeoutError:
        info = 'Нет подключения к узлу по заданому порту'
        level = 'achtung'
        #return {'delta': '-', 'host': hostname, 'not_after': None, 'not_before': None, 'expired': 'хост недоступен', 'level': level}
    
    except Exception as e:
        #print(e)
        info = 'Что то пошло не так'
        level = 'achtung'
        #return {'delta': '-', 'host': hostname, 'not_after': None, 'not_before': None, 'expired': None, 'level': level}

    return {'delta': delta, 'host': hostname, 'not_after': not_after, 'not_before': not_before, 'expired': expired, \
             'level': level, 'issuer': issuer, 'subject': subject, 'info': info }
    


def cert_download(cert_der, hostname):

    with open(f'{os.path.join(current_dir, download_dir, hostname)}.der', 'wb') as f:
        f.write(cert_der)

@app.route('/')
def get_data():
    resulted_data = []
    for key, value in get_hosts(file_name).items():
        host_info = get_host_info(key, value)
        resulted_data.append(host_info)
        #resulted_data.append({'host': host, 'not_after': '-', 'not_before': '-', 'delta': '-', 'expired': '-'})

    return render_template('plain_table.html', data=resulted_data)

@app.route('/cquery/<host>')
def query(host):
    data = []
    data.append(get_host_info(host))
    #print(data)
    return render_template('plain_table.html', data=data)

if __name__ == '__main__':
    app.debug = True
    app.run()
