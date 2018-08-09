#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright GREYC - UMR 6072 ; Université de Caen Normandie
# Esplanade de la paix
# CS 14032
# 14032 Caen CEDEX 5
# contributeur : Pierre BLONDEAU, Davy GIGAN, Cyprien GOTTSTEIN (2014)
#
# Pierre BLONDEAU - pierre.blondeau@unicaen.fr
# Davy GIGAN - davy.gigan@unicaen.fr
# Cyprien GOTTSTEIN - gottstein.cyprien@gmail.com
#
# Ce logiciel est un programme informatique servant à déchiffrer un linux
# par le réseau et sans intervention de l'utilisateur.
#
# Ce logiciel est régi par la licence CeCILL-B soumise au droit français et
# respectant les principes de diffusion des logiciels libres. Vous pouvez
# utiliser, modifier et/ou redistribuer ce programme sous les conditions
# de la licence CeCILL-B telle que diffusée par le CEA, le CNRS et l'INRIA
# sur le site "http://www.cecill.info".
#
# En contrepartie de l'accessibilité au code source et des droits de copie,
# de modification et de redistribution accordés par cette licence, il n'est
# offert aux utilisateurs qu'une garantie limitée.  Pour les mêmes raisons,
# seule une responsabilité restreinte pèse sur l'auteur du programme,  le
# titulaire des droits patrimoniaux et les concédants successifs.
#
# A cet égard  l'attention de l'utilisateur est attirée sur les risques
# associés au chargement,  à l'utilisation,  à la modification et/ou au
# développement et à la reproduction du logiciel par l'utilisateur étant
# donné sa spécificité de logiciel libre, qui peut le rendre complexe à
# manipuler et qui le réserve donc à des développeurs et des professionnels
# avertis possédant  des  connaissances  informatiques approfondies.  Les
# utilisateurs sont donc invités à charger  et  tester  l'adéquation  du
# logiciel à leurs besoins dans des conditions permettant d'assurer la
# sécurité de leurs systèmes et ou de leurs données et, plus généralement,
# à l'utiliser et l'exploiter dans les mêmes conditions de sécurité.
#
# Le fait que vous puissiez accéder à cet en-tête signifie que vous avez
# pris connaissance de la licence CeCILL-B, et que vous en avez accepté les
# termes.
#
# ================================ English ================================
#
# Copyright GREYC - UMR 6072 ; Université de Caen Normandie
# Esplanade de la paix
# CS 14032
# 14032 Caen CEDEX 5
# contributor(s) : Pierre BLONDEAU, Davy GIGAN, Cyprien GOTTSTEIN (2014)
#
# Pierre BLONDEAU - pierre.blondeau@unicaen.fr
# Davy GIGAN - davy.gigan@unicaen.fr
# Cyprien GOTTSTEIN - gottstein.cyprien@gmail.com
#
# This software is a computer program whose purpose is to decrypt a linux
# by the network without user intervention.
#
# This software is governed by the CeCILL-B license under French law and
# abiding by the rules of distribution of free software.  You can  use,
# modify and/ or redistribute the software under the terms of the CeCILL-B
# license as circulated by CEA, CNRS and INRIA at the following URL
# "http://www.cecill.info".
#
# As a counterpart to the access to the source code and  rights to copy,
# modify and redistribute granted by the license, users are provided only
# with a limited warranty  and the software's author,  the holder of the
# economic rights,  and the successive licensors  have only  limited
# liability.
#
# In this respect, the user's attention is drawn to the risks associated
# with loading,  using,  modifying and/or developing or reproducing the
# software by the user in light of its specific status of free software,
# that may mean  that it is complicated to manipulate,  and  that  also
# therefore means  that it is reserved for developers  and  experienced
# professionals having in-depth computer knowledge. Users are therefore
# encouraged to load and test the software's suitability as regards their
# requirements in conditions enabling the security of their systems and/or
# data to be ensured and,  more generally, to use and operate it in the
# same conditions as regards security.
#
# The fact that you are presently reading this means that you have had
# knowledge of the CeCILL-B license and that you accept its terms.

# vim:set ai et sta ts=4 sts=4 sw=4 tw=160:
# Last modified: lundi 2016-04-25 11:30:43 +0200

from __future__ import print_function
import os
import sys
# import ssl
import uuid
import socket
import re
import time
import traceback
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter, FileType
from configobj import ConfigObj, flatten_errors
from validate import Validator
from Crypto.PublicKey import RSA
# from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_v1_5_Cipher
from Crypto.Signature import PKCS1_v1_5 as PKCS1_v1_5_Signature
from Crypto.Hash import SHA256
from Crypto import Random
from base64 import b64encode, b64decode
from random import shuffle
import urllib3

verbose = False
dnsip = None


def error(message, extra=None):
    global verbose
    print("ERROR: ", message, file=sys.stderr)
    if verbose and extra:
        print(extra, file=sys.stderr)
    sys.exit(1)


def warning(message, extra=None):
    global verbose
    print("WARNING: ", message, file=sys.stderr)
    if verbose and extra:
        print(extra, file=sys.stderr)


create_connection_old = socket.create_connection


# Overload socket.create_connection to overwrite dns resolution
def new_create_connection(address, *args, **kwargs):
    global dnsip
    h, p = address
    if dnsip:
        h = dnsip
    return create_connection_old((h, p), *args, **kwargs)


socket.create_connection = new_create_connection


def get_passphrase(pool, id, private_key, servers, ntry, interval, timeout_retry):
    global dnsip
    signature = sign(id, private_key)

    params = {'id': id, 'signature': signature}
    number_try = ntry if ntry > 0 else -1
    while number_try != 0:
        for server in servers:
            dnsip = server['ip']
            headers = {'User-Agent': 'ntbclient'}
            try:
                response = pool.request_encode_body('POST', 'https://%s:%s/passphrase' % (server['host'], server['port']), headers=headers, fields=params)
                if response.status == 200:
                    return decrypt(response.data, private_key)
                else:
                    raise Exception('HTTP response status code error (%s)' % (response.status))
            except Exception as e:
                warning("%s(%s) : %s" % (server['host'], server['ip'], str(e)), traceback.format_exc())
        number_try = number_try - 1
        if number_try != 0:
            time.sleep(interval)
            pool.connection_pool_kw['timeout'] = timeout_retry
    error("Can't get passphrase !")


def subscribe(pool, id, private_key, public_key, servers):
    global dnsip
    signature = sign(id, private_key)

    params = {'id': id, 'signature': signature, 'public_key': public_key.exportKey("PEM")}
    for server in servers:
        dnsip = server['ip']
        headers = {'User-Agent': 'ntbclient'}
        try:
            response = pool.request_encode_body('POST', 'https://%s:%s/subscribe' % (server['host'], server['port']), headers=headers, fields=params)
            if response.status == 200:
                return response.data
            else:
                raise Exception('HTTP response status code error (%s)' % (response.status))
        except Exception as e:
            warning("%s(%s) : %s" % (server['host'], server['ip'], str(e)), traceback.format_exc())
    error("Can't subscribe !")


def sign(id, rsa_private_key):
    signer = PKCS1_v1_5_Signature.new(rsa_private_key)
    digest = SHA256.new()
    digest.update(id)
    sign = signer.sign(digest)
    return b64encode(sign)


def decrypt(encrypted, rsa_private_key):
    # TODO : How to change ? Create protocol version ?
    # Cypher choice :
    # https://www.openssl.org/docs/crypto/RSA_public_encrypt.html
    # Need server/client update to use OAEP
    # cipher = PKCS1_OAEP.new(rsakey)
    cipher = PKCS1_v1_5_Cipher.new(rsa_private_key)

    dsize = SHA256.digest_size
    # Let's assume that average data length is 15
    sentinel = Random.new().read(15 + dsize)

    decrypted = cipher.decrypt(b64decode(encrypted), sentinel)
    return b64encode(decrypted)


def gen_rsa_key(private_key, public_key):
    if not os.path.exists(private_key) and \
            not os.path.exists(public_key) and \
            os.access(os.path.dirname(private_key), os.W_OK) and \
            os.access(os.path.dirname(public_key), os.W_OK):
        new_rsa_key = RSA.generate(4096)
        new_private_key = new_rsa_key.exportKey("PEM")
        new_public_key = new_rsa_key.publickey().exportKey("PEM")
        try:
            with open(private_key, 'w') as file:
                os.chmod(private_key, 0o600)
                file.write(new_private_key)
            with open(public_key, 'w') as file:
                file.write(new_public_key)
        except Exception as e:
            error(str(e), traceback.format_exc())


def id_from_files(id_file, cache_id_file):
    try:
        with open(id_file) as file:
            idf = file.read().strip()
    except IOError:
        idf = ''
    try:
        with open(cache_id_file) as file:
            idc = file.read().strip()
    except IOError:
        idc = ''

    if idc:
        if idf and idf != idc:
            warning("The id_file and the cache_id_file are different. May be something to clean",
                    "(from file) %s != (from cache)%s" % (idf, idc))
        return idc
    if idf:
        cache_id(idf, cache_id_file)
        return idf
    error("Can't find ID, Did you subscribe ?")


def cache_id(id, cache_id_file):
    if not os.path.exists(cache_id_file):
        cache_id_file_dir = os.path.dirname(cache_id_file)
        if os.path.isdir(cache_id_file_dir):
            if os.access(cache_id_file_dir, os.W_OK):
                try:
                    with open(cache_id_file, "w") as file:
                        file.write(id)
                except IOError as e:
                    warning(str(e), traceback.format_exc())
            else:
                warning("Can't write in Cache_id_file directory")
        else:
            warning("Cache_id_file directory doesn't exist")
    else:
        warning("Cache_id_file already exist")


def get_servers(server_string, random_server, familly, error=True):
    servers = re.findall('[^,;]+', server_string.strip())
    servers_ip = []
    for s in servers:
        server = s
        port = "443"

        res = re.match("^([^:]*|[[][0-9a-zA-Z:]{3,}[]])[:]([0-9]+)$", server)
        if res:
            server = res.group(1)
            port = res.group(2)

        res2 = re.match("^[[](.*)[]]$", server)
        if res2:
            server = res2.group(1)

        if is_ipv4_address(server) and ipv4_allowed(familly) or is_ipv6_address(server) and ipv6_allowed(familly):
            servers_ip.append({"host": server, "ip": server, "port": port})
        else:
            try:
                server_addresses = set()
                for family, socktype, proto, canonname, sockaddr in socket.getaddrinfo(server, None):
                    server_addresses.add(sockaddr[0])
                for server_address in server_addresses:
                    if is_ipv4_address(server_address) and ipv4_allowed(familly) or is_ipv6_address(server_address) and ipv6_allowed(familly):
                        servers_ip.append({"host": server, "ip": server_address, "port": port})
            except socket.gaierror:
                warning("Can't resolv IP for %s" % (server), traceback.format_exc())
    if len(servers_ip) < 1 and error:
        error("Can't find any server's IP")
    if random_server:
        shuffle(servers_ip)
    return servers_ip


def get_key(key_file):
    try:
        with open(key_file) as file:
            key_text = file.read()
        key = RSA.importKey(key_text)
        return key
    except Exception as e:
        error(str(e), traceback.format_exc())


def is_ipv4_address(address):
    try:
        socket.inet_aton(address)
        return True
    except socket.error:
        return False


def is_ipv6_address(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
        return True
    except socket.error:
        return False


def ipv4_allowed(familly):
    return familly == "4" or familly == "all"


def ipv6_allowed(familly):
    return familly == "6" or familly == "all"


def main():
    global verbose
    default_conf_file = '/etc/ntbclient/ntbclient.conf'
    if not os.path.isfile(default_conf_file) or not os.access(default_conf_file, os.R_OK):
        default_conf_file = None
    conf_parser = ArgumentParser(description="NTBServer CLI", add_help=False)
    conf_parser.add_argument("-c", "--conf-file", help="Specify config file", type=FileType('r'), default=default_conf_file)

    defaults = {}
    args, remaining_argv = conf_parser.parse_known_args()
    if args.conf_file:
        config = ConfigObj(args.conf_file.name, configspec='/usr/share/ntbclient/ntbclient.conf.spec')
        validator = Validator()
        results = config.validate(validator)

        if results is not True:
            for (section_list, key, _) in flatten_errors(config, results):
                if key is not None:
                    warning('The key "%s" failed validation' % (key, ', '.join(section_list)))
        else:
            defaults = config.dict()

    parser = ArgumentParser(parents=[conf_parser], formatter_class=ArgumentDefaultsHelpFormatter)
    parser.set_defaults(**defaults)
    parser.add_argument('--id', '-i', action="store", help='Machine ID')
    parser.add_argument('--id-file', action='store', help='ID file')
    parser.add_argument('--cache-id-file', action='store', help='ID cache file')
    parser.add_argument('--private-key', '-ki', action='store', help='Private key')
    parser.add_argument('--public-key', '-ku', action='store', help='Public key')
    check_cert_parser = parser.add_mutually_exclusive_group()
    check_cert_parser.add_argument('--check-certificate', action='store_true', help='Enable check certificat')
    check_cert_parser.add_argument('--no-check-certificate', action='store_true', help='Disable check certificat')
    parser.add_argument('--ca-certificate-file', action='store', help='CA certificat file')
    familly_parser = parser.add_mutually_exclusive_group()
    familly_parser.add_argument('--ip', action='store', help='IPv4/IPv6/Both', choices=['4', '6', 'all'])
    familly_parser.add_argument('-4', action='store_true', help='IPv4 only')
    familly_parser.add_argument('-6', action='store_true', help='IPv6 only')
    parser.add_argument('--server', '-s', action='store', help='Servers')
    parser.add_argument('--server-rescue', action='store', help='Rescue servers. Can only deliver the passphrase and not subscribe. Always try in last.', default='')
    random_parser = parser.add_mutually_exclusive_group()
    random_parser.add_argument('--random-server', action='store_true', help='Enable shuffle of server addresses for request')
    random_parser.add_argument('--no-random-server', action='store_true', help='Disable shuffle of server addresses for request')
    parser.add_argument('--try', action='store', help='Number of trying for each servers', type=int)
    parser.add_argument('--interval', action='store', help='ID file', type=int)
    parser.add_argument('--timeout', action='store', help='Timeout', type=int)
    parser.add_argument('--timeout_retry', action='store', help='Timeout', type=int, default=120)
    proxy_parser = parser.add_mutually_exclusive_group()
    proxy_parser.add_argument('--use-proxy-env', action='store_true', help='Enable http(s)_proxy env proxy var')
    proxy_parser.add_argument('--no-use-proxy-env', action='store_true', help='Disable http(s)_proxy env proxy var')
    parser.add_argument('--verbose', '-v', action='store_true', help='Show more informations')
    parser.add_argument('--decode64', '-d', action='store_true', help='Decode base64 output')
    parser.add_argument('--subscribe', action='store_true', help='Subscribe to NTBServer')
    parser.add_argument('--generate-uuid', action='store_true', help='Generate new UUID')
    parser.add_argument('--output', '-o', help="Result file", type=FileType('w'), default='-')

    args = parser.parse_args(remaining_argv)

    if args.verbose:
        verbose = True

    if args.generate_uuid:
        id = str(uuid.uuid4())
        cache_id(id, args.cache_id_file)
    elif args.id:
        id = args.id
    else:
        id = id_from_files(args.id_file, args.cache_id_file)

    familly = args.ip
    if vars(args)["4"]:
        familly = "4"
    elif vars(args)["6"]:
        familly = "6"

    if args.no_check_certificate or not args.check_certificate:
        ca_certs = None
        cert_reqs = 'CERT_NONE'
        if 'disable_warnings' in dir(urllib3):
            urllib3.disable_warnings()
    else:
        cert_reqs = 'CERT_REQUIRED'
        if os.path.isfile(args.ca_certificate_file) and os.access(args.ca_certificate_file, os.R_OK):
            ca_certs = args.ca_certificate_file
        else:
            ca_certs = "/etc/ssl/certs/ca-certificates.crt"
            if not os.path.isfile(ca_certs) or not os.access(ca_certs, os.R_OK):
                error("Can't find ca cert file : %s" % (ca_certs))

    pool = urllib3.PoolManager(cert_reqs=cert_reqs, ca_certs=ca_certs, timeout=args.timeout, retries=urllib3.Retry(0))

    random_server = False if args.no_random_server else args.random_server
    servers = get_servers(args.server, random_server, familly)

    if args.subscribe:
        gen_rsa_key(args.private_key, args.public_key)
        private_key = get_key(args.private_key)
        public_key = get_key(args.public_key)
        subscribe(pool, id, private_key, public_key, servers)
    else:
        servers_rescue = get_servers(args.server_rescue, False, familly, False)
        servers.extend(servers_rescue)

        private_key = get_key(args.private_key)
        passphrase = get_passphrase(pool, id, private_key, servers, vars(args)['try'], args.interval, args.timeout_retry)
        if args.decode64:
            args.output.write(b64decode(passphrase))
        else:
            args.output.write(passphrase)
    sys.exit(0)


# Execution si je n'ai pas été chargé par un autre programme
if __name__ == "__main__":
    main()
