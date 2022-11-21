from sys import executable
from os import system
from subprocess import check_output
from random import choice
from time import sleep
from requests import get, put

BASE_API_URL = "https://vmkbqkse7k.execute-api.us-east-1.amazonaws.com"
COMPARMENT_OCID = "ocid1.compartment.oc1..aaaaaaaakjio6ufxj7mjifujudmsyonjwv7eagvusxqa4c4vtge43jzcgwlq"

cloud_init_yml = """
#cloud-config

disable_root: false
swap:
  filename: /swap.img
  size: "auto"
  maxsize: 4294967296
users:
  - name: root
    lock_passwd: true
    ssh_authorized_keys:
      - {ssh_public_key}
"""

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

# Displaying header texts
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

# Repeat until success
def repeat_until_success(function):
    for _ in range(60):
        try: return function()
        except: sleep(3)
    raise Exception("Error waiting")

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

# Fetch SSH keys of machine
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

# Creating all OCI clients with machine config
status = Status("Initiating OCI clients ...", spinner=choice(spinner_types))
status.start()
oci_config = config.from_file()
identity_client = identity.IdentityClient(oci_config)
status.stop()
print("✅  Initiated OCI clients ...")

# Switch clients to home region
status = Status("Switching to home region ...", spinner=choice(spinner_types))
status.start()
regions = identity_client.list_region_subscriptions(oci_config.get("tenancy")).data
oci_config["region"] = [x.region_name for x in regions if x.is_home_region][0]
identity_client = identity.IdentityClient(oci_config)
compute_client = core.ComputeClient(oci_config)
network_client = core.VirtualNetworkClient(oci_config)
status.stop()
print("✅  Switched to home region ...")

# Skip or create tenant policy for accessing external os images
status = Status("Creating Endorse Policy ...", spinner=choice(spinner_types))
status.start()
policy_statements = ["Endorse any-user to read instance-family in any-tenancy"]
policies: List[identity.models.Policy] = identity_client.list_policies(compartment_id=oci_config.get("tenancy"), name="external-image-access").data
if len(policies):
    policy = policies.pop()
else:
    policy: identity.models.Policy = identity_client.create_policy({"name": "external-image-access", "compartmentId": oci_config.get("tenancy"), "description": "external image access policy for official bin2bin images", "statements": policy_statements}).data
repeat_until_success(lambda: wait_until(identity_client, identity_client.get_policy(policy.id), 'lifecycle_state', 'ACTIVE'))
status.stop()
print("✅  Created Endorse Policy ...")

# Skip or Creating bin2bin compartment
status = Status("Creating Compartment ...", spinner=choice(spinner_types))
status.start()
compartments: List[identity.models.Compartment] = identity_client.list_compartments(compartment_id=oci_config.get("tenancy"), name="bin2bin").data
if len(compartments):
    compartment = compartments.pop()
else:
    compartment: identity.models.Compartment = identity_client.create_compartment({"compartmentId": oci_config.get("tenancy"), "name": "bin2bin", "description": "Compartment for deploying bin2bin related resources"}).data
repeat_until_success(lambda: wait_until(identity_client, identity_client.get_compartment(compartment.id), 'lifecycle_state', 'ACTIVE'))
status.stop()
print("✅  Created Compartment ...")

# Skip or Create default vitual cloud network
status = Status("Creating Virtual Cloud Network ...", spinner=choice(spinner_types))
status.start()
vcns: List[core.models.Vcn] = network_client.list_vcns(compartment_id=compartment.id, display_name="default").data
if len(vcns):
    vcn = vcns.pop()
else:
    vcn: core.models.Vcn = network_client.create_vcn({"cidrBlock": "10.0.0.0/16", "compartmentId": compartment.id, "displayName": "default"}).data
repeat_until_success(lambda: wait_until(network_client, network_client.get_vcn(vcn.id), 'lifecycle_state', 'AVAILABLE'))
status.stop()
print("✅  Created Virtual Cloud Network ...")

# Skip or Create default security rules for virtual machine
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
repeat_until_success(lambda: wait_until(network_client, network_client.get_security_list(security_list.id), 'lifecycle_state', 'AVAILABLE'))
status.stop()
print("✅  Created Security Rules ...")

# Skip or Create default internet gateway for virtual machine
status = Status("Creating Internet Gateway ...", spinner=choice(spinner_types))
status.start()
internet_gateways: List[core.models.InternetGateway] = network_client.list_internet_gateways(compartment_id=compartment.id, vcn_id=vcn.id, display_name="default").data
if len(internet_gateways):
    internet_gateway = internet_gateways.pop()
else:
    internet_gateway: core.models.InternetGateway = network_client.create_internet_gateway({"displayName": "default", "compartmentId": compartment.id, "vcnId": vcn.id, "isEnabled": True}).data
repeat_until_success(lambda: wait_until(network_client, network_client.get_internet_gateway(internet_gateway.id), 'lifecycle_state', 'AVAILABLE'))
status.stop()
print("✅  Created Internet Gateway ...")

# Skip or Create default route table for default internet gateway
status = Status("Creating Route Table ...", spinner=choice(spinner_types))
status.start()
route_tables: List[core.models.RouteTable] = network_client.list_route_tables(compartment_id=compartment.id, vcn_id=vcn.id, display_name="default").data
if len(route_tables):
    route_table = route_tables.pop()
else:
    route_table: core.models.RouteTable = network_client.create_route_table({"displayName": "default", "vcnId": vcn.id, "routeRules": [{"cidrBlock": "0.0.0.0/0", "networkEntityId": internet_gateway.id}], "compartmentId": compartment.id}).data
repeat_until_success(lambda: wait_until(network_client, network_client.get_route_table(route_table.id), 'lifecycle_state', 'AVAILABLE'))
status.stop()
print("✅  Created Route Table ...")

# Skip or Create default subnet
status = Status("Creating Subnet ...", spinner=choice(spinner_types))
status.start()
subnets: List[core.models.Subnet] = network_client.list_subnets(compartment_id=compartment.id, vcn_id=vcn.id, display_name="default").data
if len(subnets):
    subnet = subnets.pop()
else:
    subnet: core.models.Subnet = network_client.create_subnet({"displayName": "default", "cidrBlock": "10.0.0.0/24", "routeTableId": route_table.id, "securityListIds": [security_list.id], "vcnId": vcn.id, "compartmentId": compartment.id}).data
repeat_until_success(lambda: wait_until(network_client, network_client.get_subnet(subnet.id), 'lifecycle_state', 'AVAILABLE'))
status.stop()
print("✅  Created Subnet ...")

# Get default availability zone for free instance
status = Status("Fetching Availability Domain ...", spinner=choice(spinner_types))
status.start()
availability_domains: List[identity.models.AvailabilityDomain] = identity_client.list_availability_domains(compartment_id=oci_config.get("tenancy")).data
for availability_domain in availability_domains:
    shapes: List[core.models.Shape] = compute_client.list_shapes(oci_config.get("tenancy"), availability_domain = availability_domain.name).data
    if len([x for x in shapes if x.shape == "VM.Standard.E2.1.Micro"]): break
status.stop()
print("✅  Fetched Availability Domain ...")

# Skip or Create virtual machine based on the configuration
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
repeat_until_success(lambda: wait_until(compute_client, compute_client.get_instance(instance.id), 'lifecycle_state', 'RUNNING'))
status.stop()
print("✅  Created Machine ...")

# Wait for 60 seconds untill all services like SSH, wireguard, etc.. comes up
status = Status("Waiting for services ...", spinner=choice(spinner_types))
status.start(); sleep(60); status.stop()

# Get public ipv4 for the created virtual machine
status = Status("Fetching Machine IP Address ...", spinner=choice(spinner_types))
status.start()
vnic: List[core.models.VnicAttachment] = compute_client.list_vnic_attachments(compartment_id=compartment.id, instance_id=instance.id).data
public_ip = network_client.get_vnic(vnic_id=vnic[0].vnic_id).data.public_ip
status.stop()
print("✅  Fetched Machine IP Address ...")

# Update the machine's public ip back to bin2bin
status = Status("Updating Machine IP Address ...", spinner=choice(spinner_types))
status.start()
put(f"{BASE_API_URL}/custom/put_machine_public_ip", json = {"public_ip": public_ip}, headers=auth_headers)
status.stop()
print("✅  Updated Machine IP Address ...")
print("", Align.center(Text("😃  Virtual machine created successfully 😃", style="bright_cyan")), "")







# Define tenancy Acceptor as ${var.tenancy_ocid_b}
# Endorse group Administrators to manage local-peering-to in tenancy Acceptor
# Endorse group Administrators to associate local-peering-gateways in compartment ${var.compartment_name_a} with local-peering-gateways in tenancy Acceptor
# Allow group Administrators to manage local-peering-from in compartment ${var.compartment_name_a}

# Define tenancy Requestor as ${var.tenancy_ocid_a}
# Define group RequestorGrp as ocid1.group.oc1..aaaaaaaachg2jo6vblnpg7ccujaez6as7tvpviefw33yhygijjkanwpb6fea
# Allow group Administrators to manage local-peering-from in compartment ${var.compartment_name_b}
# Admit group RequestorGrp of tenancy Requestor to manage local-peering-to in compartment ${var.compartment_name_b}
# Admit group RequestorGrp of tenancy Requestor to associate local-peering-gateways in tenancy Requestor with local-peering-gateways in compartment ${var.compartment_name_b}

# oci os ns get --compartment-id "ocid1.tenancy.oc1..aaaaaaaajh362ldvjjc3sy3iiyvca7l5iy72rq4yrdbp5nfeluk2whiav6nq"

# ocid1.bucket.oc1.iad.aaaaaaaakzeyjfz376r2sp6wwkbg5mzxheli2zskl6v6rrprc2bu3espstna

# Define tenancy vendorX as ocid1.tenancy.oc1..aaaaaaaa5axzt6eajsqn3d5l73k4ibqnih3yof74e3sd6q5vejppxl7dmleq
# Define group Administrators as ocid1.group.oc1..aaaaaaaaeg33rmxwkbuml22ffpdegdsezzw567upz3tsqz4g3kdzeo3xhvba
# Admit group Administrators of tenancy vendorX to read instance-family in tenancy

# Define tenancy companyABC as ocid1.tenancy.oc1..aaaaaaaajh362ldvjjc3sy3iiyvca7l5iy72rq4yrdbp5nfeluk2whiav6nq
# Endorse group Administrators to read instance-family in tenancy companyABC

# Admit any-user of any-tenancy to read instance-images in tenancy

# Endorse group Administrators to read instance-family in any-tenancy

# oci compute instance get --instance-id "ocid1.instance.oc1.iad.anuwcljtq2o2eiqcfqeb3zzoo45mrxabhyafoyjqvcvp5vdns3dqy3dfqmtq"
# oci compute image get --image-id "ocid1.image.oc1.iad.aaaaaaaafaidnhl67ceda5euqxobnrbqc7moka5dvampxu52ivbde7fuhfya"
