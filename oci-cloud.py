from sys import executable
from os import system
from subprocess import check_output
from random import choice
from time import sleep
from requests import get, put

BASE_API_URL = "https://vmkbqkse7k.execute-api.us-east-1.amazonaws.com"

try:
    from rich.panel import Panel
except:
    system('clear'); print("🥺  Please wait while loading libraries ...")
    check_output([executable, "-m", "pip", "install", "--user", "rich"])
    import site; from importlib import reload; reload(site)

spinner_types = ["earth", "smiley", "monkey", "moon", "runner"]

from rich import print
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich.box import ASCII
from rich.status import Status

header_texts = [
    Text("\n", justify="center"),
    Text("Welcome to OCI Virtual Machine Setup", justify="center", style="bold magenta"),
    Text("\n", justify="center"),
    Text("Developed By: bin2bin", justify="center", style="bold green"),
    Text("\n", justify="center"),
]

panel_text = Align.center(Text.assemble(*header_texts, justify="center"))
panel = Panel(panel_text, box=ASCII, title="Oracle Cloud Infrastructure Platform", width=80)
system('clear') ;print("", Align.center(panel), "")

# Initiating SDK Components
status = Status("Initiating SDK ...", spinner=choice(spinner_types))
status.start()
from oci import config, wait_until
from oci import identity, core
from typing import List
from base64 import b64encode
from argparse import ArgumentParser
status.stop()
print("✅  Initiating SDK ...")

cloud_init_yml = """
#cloud-config

swap:
  filename: /swapfile
  size: "auto"
  maxsize: 17179869184

package_update: true
disable_root: false

users:
  - name: root
    lock_passwd: true
    ssh_authorized_keys:
      - {ssh_public_key}

bootcmd:
  - systemctl start wg-quick@wg0.service

runcmd:
  - echo 'PermitRootLogin prohibit-password' >> /etc/ssh/sshd_config
  - systemctl restart ssh
  - echo "DNSStubListener=no" >> /etc/systemd/resolved.conf
  - systemctl restart systemd-resolved
  - echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf && sysctl -p
  - apt-get -y install podman wireguard dnsmasq net-tools
  - rm -f /etc/dnsmasq.conf && echo "bind-interfaces" >> /etc/dnsmasq.conf
  - echo "listen-address=0.0.0.0" >> /etc/dnsmasq.conf
  - systemctl restart dnsmasq
  - mkdir -p /etc/wireguard && wg genkey > /etc/wireguard/dummy.key
  - echo "[Interface]" > /etc/wireguard/wg0.conf
  - echo "PrivateKey = $(cat /etc/wireguard/dummy.key)" >> /etc/wireguard/wg0.conf
  - echo "Address = 10.10.0.1/32" >> /etc/wireguard/wg0.conf
  - echo "ListenPort = 51820" >> /etc/wireguard/wg0.conf
  - systemctl enable wg-quick@wg0.service
  - iptables -I INPUT -p udp -m multiport --dport 53,51820 -j ACCEPT
  - iptables -I INPUT -p tcp -m multiport --dport 53,80,443 -j ACCEPT
  - export NTWKIF=$(route -n | awk '$1 == "0.0.0.0" {print $8}')
  - iptables -I FORWARD -d 10.10.0.0/24 -i $NTWKIF -o wg0 -j ACCEPT
  - iptables -I FORWARD -s 10.10.0.0/24 -i wg0 -o $NTWKIF -j ACCEPT
  - iptables -t nat -I POSTROUTING -s 10.10.0.0/24 -o $NTWKIF -j MASQUERADE
  - rm -rf /var/lib/{apt,dpkg,cache,log}/
"""

status = Status("Fetching SSH public keys ...", spinner=choice(spinner_types))
status.start()
parser = ArgumentParser()
parser.add_argument('--token', type=str, required=True)
args = parser.parse_args()
auth_headers = {"Authorization": "Bearer " + args.token}
response = get(f"{BASE_API_URL}/custom/get_machine_public_key", headers=auth_headers)
machine_id = response.json()["machine_id"]
public_key = response.json()["public_key"]
status.stop()
print("✅  Fetched SSH public keys ...")


status = Status("Initiating OCI clients ...", spinner=choice(spinner_types))
status.start()
oci_config = config.from_file()
identity_client = identity.IdentityClient(oci_config)
compute_client = core.ComputeClient(oci_config)
network_client = core.VirtualNetworkClient(oci_config)
status.stop()
print("✅  Initiated OCI clients ...")


status = Status("Creating Compartment ...", spinner=choice(spinner_types))
status.start()
compartments: List[identity.models.Compartment] = identity_client.list_compartments(compartment_id=oci_config.get("tenancy"), name="bin2bin").data
if len(compartments):
    compartment = compartments.pop()
else:
    compartment: identity.models.Compartment = identity_client.create_compartment({"compartmentId": oci_config.get("tenancy"), "name": "bin2bin", "description": "Compartment for deploying bin2bin related resources"}).data
wait_until(identity_client, identity_client.get_compartment(compartment.id), 'lifecycle_state', 'ACTIVE')
status.stop()
print("✅  Created Compartment ...")


status = Status("Creating Virtual Cloud Network ...", spinner=choice(spinner_types))
status.start()
vcns: List[core.models.Vcn] = network_client.list_vcns(compartment_id=compartment.id, display_name="default").data
if len(vcns):
    vcn = vcns.pop()
else:
    vcn: core.models.Vcn = network_client.create_vcn({"cidrBlock": "10.0.0.0/16", "compartmentId": compartment.id, "displayName": "default"}).data
wait_until(network_client, network_client.get_vcn(vcn.id), 'lifecycle_state', 'AVAILABLE')
status.stop()
print("✅  Created Virtual Cloud Network ...")


status = Status("Creating Security Rules ...", spinner=choice(spinner_types))
status.start()
egress_security_rules = [
    {'isStateless': False, 'protocol': 'all', 'destination': '0.0.0.0/0', 'destinationType': 'CIDR_BLOCK'}
]
ingress_security_rules = [
    {'isStateless': False, 'protocol': '6', 'source': '0.0.0.0/0', 'sourceType': 'CIDR_BLOCK', 'tcpOptions': {'destinationPortRange': {'max': 22, 'min': 22}}},
    {'isStateless': False, 'protocol': '6', 'source': '0.0.0.0/0', 'sourceType': 'CIDR_BLOCK', 'tcpOptions': {'destinationPortRange': {'max': 443, 'min': 443}}},
    {'isStateless': False, 'protocol': '17', 'source': '0.0.0.0/0', 'sourceType': 'CIDR_BLOCK', 'udpOptions': {'destinationPortRange': {'max': 51820, 'min': 51820}}},
]
security_lists: List[core.models.SecurityList] = network_client.list_security_lists(compartment_id=compartment.id, vcn_id=vcn.id, display_name="default").data
if len(security_lists):
    security_list = security_lists.pop()
else:
    security_list: core.models.SecurityList = network_client.create_security_list({"vcnId": vcn.id, "displayName": "default", "egressSecurityRules": egress_security_rules, "ingressSecurityRules": ingress_security_rules, "compartmentId": compartment.id}).data
wait_until(network_client, network_client.get_security_list(security_list.id), 'lifecycle_state', 'AVAILABLE')
status.stop()
print("✅  Created Security Rules ...")


status = Status("Creating Internet Gateway ...", spinner=choice(spinner_types))
status.start()
internet_gateways: List[core.models.InternetGateway] = network_client.list_internet_gateways(compartment_id=compartment.id, vcn_id=vcn.id, display_name="default").data
if len(internet_gateways):
    internet_gateway = internet_gateways.pop()
else:
    internet_gateway: core.models.InternetGateway = network_client.create_internet_gateway({"displayName": "default", "compartmentId": compartment.id, "vcnId": vcn.id, "isEnabled": True}).data
wait_until(network_client, network_client.get_internet_gateway(internet_gateway.id), 'lifecycle_state', 'AVAILABLE')
status.stop()
print("✅  Created Internet Gateway ...")


status = Status("Creating Route Table ...", spinner=choice(spinner_types))
status.start()
route_tables: List[core.models.RouteTable] = network_client.list_route_tables(compartment_id=compartment.id, vcn_id=vcn.id, display_name="default").data
if len(route_tables):
    route_table = route_tables.pop()
else:
    route_table: core.models.RouteTable = network_client.create_route_table({"displayName": "default", "vcnId": vcn.id, "routeRules": [{"cidrBlock": "0.0.0.0/0", "networkEntityId": internet_gateway.id}], "compartmentId": compartment.id}).data
wait_until(network_client, network_client.get_route_table(route_table.id), 'lifecycle_state', 'AVAILABLE')
status.stop()
print("✅  Created Route Table ...")


status = Status("Creating Subnet ...", spinner=choice(spinner_types))
status.start()
subnets: List[core.models.Subnet] = network_client.list_subnets(compartment_id=compartment.id, vcn_id=vcn.id, display_name="default").data
if len(subnets):
    subnet = subnets.pop()
else:
    subnet: core.models.Subnet = network_client.create_subnet({"displayName": "default", "cidrBlock": "10.0.0.0/24", "routeTableId": route_table.id, "securityListIds": [security_list.id], "vcnId": vcn.id, "compartmentId": compartment.id}).data
wait_until(network_client, network_client.get_subnet(subnet.id), 'lifecycle_state', 'AVAILABLE')
status.stop()
print("✅  Created Subnet ...")


status = Status("Fetching OS list ...", spinner=choice(spinner_types))
status.start()
os_list: List[core.models.Image] = compute_client.list_images(compartment_id=compartment.id, operating_system="Canonical Ubuntu", lifecycle_state="AVAILABLE", operating_system_version="22.04 Minimal").data
os_image: core.models.Image = sorted(os_list, key = lambda x: x.display_name).pop()
status.stop()
print("✅  Fetched OS list ...")


status = Status("Fetching Availability Domain ...", spinner=choice(spinner_types))
status.start()
availability_domains: List[identity.models.AvailabilityDomain] = identity_client.list_availability_domains(compartment_id=oci_config.get("tenancy")).data
for availability_domain in availability_domains:
    shapes: List[core.models.Shape] = compute_client.list_shapes(oci_config.get("tenancy"), availability_domain = availability_domain.name).data
    if len([x for x in shapes if x.shape == "VM.Standard.E2.1.Micro"]): break
status.stop()
print("✅  Fetched Availability Domain ...")


status = Status("Creating Machine ...", spinner=choice(spinner_types))
status.start()
cloud_init = cloud_init_yml.replace("{ssh_public_key}", public_key)
instances: List[core.models.Instance] = compute_client.list_instances(compartment_id=compartment.id, display_name=machine_id).data
if len(instances):
    instance = instances.pop()
else:
    instance: core.models.Instance = compute_client.launch_instance({
        "agent_config": {"are_all_plugins_disabled": True},
        "availabilityDomain": availability_domain.name,
        "compartmentId": compartment.id,
        "shape": "VM.Standard.E2.1.Micro",
        "metadata": {
            'ssh_authorized_keys': public_key,
            'user_data': b64encode(cloud_init.encode()).decode()
        },
        "displayName": machine_id,
        "sourceDetails": {
            "imageId": os_image.id, "sourceType": "image", 
            "bootVolumeSizeInGBs": 100, "bootVolumeVpusPerGB": 120
        },
        "createVnicDetails": {"subnetId": subnet.id, "assignPublicIp": True},
    }).data
wait_until(compute_client, compute_client.get_instance(instance.id), 'lifecycle_state', 'RUNNING')
status.stop()
print("✅  Created Machine ...")


status = Status("Waiting for services ...", spinner=choice(spinner_types))
status.start(); sleep(60); status.stop()


status = Status("Fetching Machine IP Address ...", spinner=choice(spinner_types))
status.start()
vnic: List[core.models.VnicAttachment] = compute_client.list_vnic_attachments(compartment_id=compartment.id, instance_id=instance.id).data
public_ip = network_client.get_vnic(vnic_id=vnic[0].vnic_id).data.public_ip
status.stop()
print("✅  Fetched Machine IP Address ...")


status = Status("Updating Machine IP Address ...", spinner=choice(spinner_types))
status.start()
put(f"{BASE_API_URL}/custom/put_machine_public_ip", json = {"public_ip": public_ip}, headers=auth_headers)
status.stop()
print("✅  Updated Machine IP Address ...")
print("", Align.center(Text("😃  Virtual machine created successfully 😃", style="bright_cyan")), "")