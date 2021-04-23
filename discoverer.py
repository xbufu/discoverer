#!/usr/bin/env python3

import socket
import concurrent.futures
import xml.etree.ElementTree as ET
import subprocess
import argparse
import random
import os
import string
import threading
from queue import Queue

def host_discovery(target, exclude_ip=""):
    tmp = "/tmp/" + "".join(random.choice(string.ascii_letters) for i in range(12))
    if exclude_ip:
        subprocess.call(["nmap", "-sn", "-oX", tmp, "--exclude", exclude_ip, target], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        subprocess.call(["nmap", "-sn", "-oX", tmp, target], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    tree = ET.parse(tmp)
    root = tree.getroot()

    hosts = [addr.attrib["addr"] for addr in root.iter("address") if addr.attrib["addrtype"] == "ipv4"]

    os.remove(tmp)

    return hosts

def os_detection(hosts):
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(os_scan, host) for host in hosts]

def os_scan(host):
    f = "/tmp/" + host + "_os.xml"
    subprocess.call(["nmap", "-Pn", "--disable-arp-ping", "-O", "--osscan-guess", "-oX", f, "--top-ports", "100", host], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    tree = ET.parse(f)
    root = tree.getroot()

    i = 0
    for osmatch in root.iter("osmatch"):
        RESULTS[host]["OS"].append(f"{osmatch.attrib['name']} ({osmatch.attrib['accuracy']}%)")
        i += 1
        if i == 3:
            break

    os.remove(f)

def port_scan(hosts):
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = []
        for host in hosts:
            futures.append(executor.submit(tcp_scan, host))
            futures.append(executor.submit(udp_scan, host))

def tcp_scan(host):
    socket.setdefaulttimeout(0.5)
    print_lock = threading.Lock()

    def check_port(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        try:
            conx = s.connect((host, port))
            with print_lock:
                p = str(port)
                print(host + ":tcp:" + p)
                RESULTS[host]["ports"]["tcp"][p] = {}
            conx.close()

        except (ConnectionRefusedError, AttributeError, OSError):
            pass

    def threader():
        while True:
            worker = q.get()
            check_port(worker)
            q.task_done()
        
    q = Queue()
        
    for _ in range(200):
        t = threading.Thread(target=threader)
        t.daemon = True
        t.start()

    for worker in range(1, 65536):
        q.put(worker)

    q.join()

def udp_scan(host):
    f = "/tmp/" + host + "_udp.xml"
    subprocess.call(["nmap", "-sU", "-Pn", "--disable-arp-ping", "-T4", "--open", "-oX", f, "--top-ports", "25", host], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    tree = ET.parse(f)
    root = tree.getroot()

    for port in root.iter("port"):
        for node in port.iter():
            if node.tag == "port":
                RESULTS[host]["ports"]["udp"][node.attrib['portid']] = {}

    os.remove(f)

def service_detection(hosts):
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(service_scan, host) for host in hosts]

def service_scan(host):
    f = "/tmp/" + host + "_services.xml"
    tcp_ports = RESULTS[host]["ports"]["tcp"].keys()
    udp_ports = RESULTS[host]["ports"]["udp"].keys()

    for port in tcp_ports:
        RESULTS[host]["ports"]["tcp"][port] = {"service": "", "version": ""}
    for port in udp_ports:
        RESULTS[host]["ports"]["udp"][port] = {"service": "", "version": ""}

    ports = ""
    scan_type = "-s"
    if tcp_ports:
        ports += "T:"
        ports += ",".join(tcp_ports)
        scan_type += "S"
    if udp_ports:
        if ports:
            ports += ","
        ports += "U:"
        ports += ",".join(udp_ports)
        scan_type += "U"

    if "S" in scan_type or "U" in scan_type:
        RESULTS[host]["nmap_output"] = subprocess.check_output(["nmap", scan_type, "-sCV", "--version-all", "--open", "-Pn", "--disable-arp-ping", "-oX", f, "-p", ports, host], stderr=subprocess.DEVNULL).decode()

    tree = ET.parse(f)
    root = tree.getroot()

    tcp_ports = [port.attrib["portid"] for port in root.iter("port") if port.attrib["protocol"] == "tcp"]
    udp_ports = [port.attrib["portid"] for port in root.iter("port") if port.attrib["protocol"] == "udp"]
    services = []
    versions = []

    for port in root.iter("port"):    
            for node in port.iter():
                if node.tag == "service":
                    services.append(node.attrib["name"])
                    version = ""
                    if "product" in node.attrib:
                        if version:
                            version += " "
                        version += node.attrib["product"]
                    if "version" in node.attrib:
                        if version:
                            version += " "
                        version += node.attrib["version"]
                    if "extrainfo" in node.attrib:
                        if version:
                            version += " "
                        version += node.attrib["extrainfo"]
                    versions.append(version)

    i = 0
    for port in tcp_ports:
        RESULTS[host]["ports"]["tcp"][port] = {"service": services[i], "version": versions[i]}
        i += 1

    for port in udp_ports:
        RESULTS[host]["ports"]["udp"][port] = {"service": services[i], "version": versions[i]}
        i += 1

    os.remove(f)
    
def main():
    subprocess.call('clear', shell=True)

    global RESULTS
    RESULTS = {}

    parser = argparse.ArgumentParser()

    parser.add_argument("target", metavar="IP/CIDR", type=str, help="IP or CIDR range to scan")
    parser.add_argument("--exclude", metavar="IP", type=str, help="IP to exclude from scanning")
    args = parser.parse_args()

    target = args.target
    exclude_ip = args.exclude

    banner = """
     _____ _____  _____  _____ ______      ________ _____  ______ _____  
    |  __ \_   _|/ ____|/ ____/ __ \ \    / /  ____|  __ \|  ____|  __ \ 
    | |  | || | | (___ | |   | |  | \ \  / /| |__  | |__) | |__  | |__) |
    | |  | || |  \___ \| |   | |  | |\ \/ / |  __| |  _  /|  __| |  _  / 
    | |__| || |_ ____) | |___| |__| | \  /  | |____| | \ \| |____| | \ \ 
    |_____/_____|_____/ \_____\____/   \/   |______|_|  \_\______|_|  \_\
        
    """

    print(banner)
    print()

    print("\n########## Host Discovery ##########\n")
    hosts = host_discovery(target, exclude_ip)
    print("\t{:<30}".format("IP"))
    print('-' * 30)
    for host in hosts:
        RESULTS[host] = {"ports": {"tcp": {}, "udp": {}}, "OS": []}
        print("\t{:<20}".format(host))
    print()

    print("########## OS Detection ##########\n")
    os_detection(hosts)
    print("\t{:<20}   {:<50}".format("IP", "OS"))
    print('-' * 100)
    for host in hosts:
        print("\t{:<20}   {:<50}".format(host, ", ".join(RESULTS[host]["OS"])))
    print()

    print("########## Port Scan ##########")
    print()
    port_scan(hosts)
    for host in hosts:
        print("\n### " + host + " ###\n")
        print("\t{:<8}   {:<8}".format("PROTOCOL", "PORT"))
        print('-' * 30)
        for port in RESULTS[host]["ports"]["tcp"].keys():
            print("\t{:<8}   {:<8}".format("tcp", port))
        for port in RESULTS[host]["ports"]["udp"].keys():
            print("\t{:<8}   {:<8}".format("udp", port))
    print()
    
    print("########## Service Detection & Script Scan ##########")
    service_detection(hosts)
    for host in hosts:
        print("\n### " + host + " ###\n")
        print(RESULTS[host]["nmap_output"])
        print("#" * 50)
        print("\n\n")

if __name__ == "__main__":
    main()