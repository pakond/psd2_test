import http.client
import OpenSSL.crypto
import uuid
import hashlib
import binascii
import base64
import re

from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto import Random

secret_client = 'secre client key'
id_client = 'id cliente'
aspsp = 'banco'
certificado_publico = 'public_key.txt'
certificado_privado = 'private_key.txt'

def firmar(mensaje, archivo):
    h = SHA256.new(mensaje.encode())
    archivo_key = open(archivo, 'r')
    private_key = RSA.import_key(archivo_key.read())
    archivo_key.close()
    signature = pss.new(private_key).sign(h)
    signature = base64.b64encode(signature)
    signature = signature.decode()
    return signature

def depurar_public_key(archivo):
    archivo_cert = open(archivo, 'r')
    cert = archivo_cert.read()
    archivo_cert.close()
    cert = cert.replace("-----BEGIN CERTIFICATE-----", "")
    cert = cert.replace("-----END CERTIFICATE-----", "")
    cert = cert.replace("\n", "")
    #cert = base64.b64encode(cert.encode())
    return cert

def crear_KeyId(certificado):
    cert = open(certificado, 'r')
    key = OpenSSL.crypto.load_certificate(type=OpenSSL.crypto.FILETYPE_PEM, buffer=cert.read())
    cert.close()

    serial_number = key.get_serial_number()
    cert_subject = key.get_subject()
    cert_tuple = cert_subject.get_components()

    KeyId_dic = {}
    for dicc in cert_tuple:
        key = dicc[0].decode()
        value = dicc[1].decode()
        KeyId_dic[key] = value

    KeyId_dic['CN'] = KeyId_dic['CN'].replace('%20', ' ')
    KeyId = 'SN='+ str(serial_number) +',CA=C='+ KeyId_dic['C'] +',ST='+ KeyId_dic['ST'] +',L='+ KeyId_dic['L'] +',O='+ KeyId_dic['O'] +',OU='+ KeyId_dic['OU'] +',CN='+ KeyId_dic['CN']
    return KeyId

x_request_id = str(uuid.uuid4())

payload = "{\"cardNumber\":\"1111-1111-1111-1111\",\"account\":{\"iban\":\"ES1111111111111111111111\",\"bban\":\"20385778983000760236\",\"pan\":\"1234567891234567\",\"msisdn\":\"195198741874\",\"currency\":\"EUR\"},\"payee\":\"Comercio\",\"instructedAmount\":{\"currency\":\"EUR\",\"amount\":\"150.03\"}}"

base64_digest = base64.b64encode(hashlib.sha256(payload.encode()).digest()).decode()
base64_digest = 'SHA-256=' + base64_digest

public_key = depurar_public_key(certificado_publico)

conn = http.client.HTTPSConnection("apis-i.redsys.es:20443")

mensaje_firma = 'algorithm="SHA-256"\ndigest: '+ base64_digest + '\nx-request-id: '+ x_request_id
signature = firmar(mensaje_firma, certificado_privado)

KeyId = crear_KeyId(certificado_publico)
firma_final = 'Signature:keyId="'+ KeyId + '",algorithm="SHA-256",headers="digest x-request-id",signature="'+ signature +'"'

headers = {
    'x-ibm-client-id': id_client,
    'x-request-id': x_request_id,
    'digest': base64_digest,
    'signature': firma_final,
    'tpp-signature-certificate': public_key,
    'content-type': "application/json",
    'accept': "application/json"
}

conn.set_debuglevel(1)
conn.request("POST", "/psd2/xs2a/api-entrada-xs2a/services/"+ aspsp +"/v1/funds-confirmations", payload, headers)

res = conn.getresponse()
data = res.read()

print(data.decode("utf-8"))