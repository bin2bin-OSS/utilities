from os import system
from time import sleep
from requests import get, put
system('clear')

BASE_API_URL = "https://vmkbqkse7k.execute-api.us-east-1.amazonaws.com"
CLOUD_INIT_TEMPLATE = """
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

print("="* 30)
print("😃  Virtual Machine Setup 😃")
print("="* 30 + "\n")

# Repeat until success
def repeat_until_success(function):
    for _ in range(60):
        try: return function()
        except: sleep(3)
    raise Exception("Error waiting")

# Initiating SDK Components
print("🌼  Initiating SDK ...", end="\r")
from oci import config, wait_until
from oci import identity, core
from typing import List
from base64 import b64encode
from argparse import ArgumentParser
print("✅  Initiated SDK ...")

# Fetch SSH keys of machine
print("🌼  Fetching SSH public keys ...", end="\r")
parser = ArgumentParser()
parser.add_argument('--token', type=str, required=True)
args = parser.parse_args()
auth_headers = {"Authorization": "Bearer " + args.token}
response = get(f"{BASE_API_URL}/custom/get_machine_public_key", headers=auth_headers)
machine_id = response.json()["machine_id"]
public_key = response.json()["public_key"]
print("✅  Fetched SSH public keys ...")

# Creating all OCI clients with machine config
print("🌼  Initiating OCI clients ...", end="\r")
oci_config = config.from_file()
identity_client = identity.IdentityClient(oci_config)
print("✅  Initiated OCI clients ...")

# Switch clients to home region
print("🌼  Switching to home region ...", end="\r")
regions = identity_client.list_region_subscriptions(oci_config.get("tenancy")).data
oci_config["region"] = [x.region_name for x in regions if x.is_home_region][0]
identity_client = identity.IdentityClient(oci_config)
compute_client = core.ComputeClient(oci_config)
network_client = core.VirtualNetworkClient(oci_config)
print("✅  Switched to home region ...")

# Skip or create tenant policy for accessing external os images
print("🌼  Creating Endorse Policy ...", end="\r")
policy_model = identity.models.CreatePolicyDetails(
    name="external-image-access", compartment_id=oci_config.get("tenancy"), 
    description="external image access policy for official bin2bin images", 
    statements=["Endorse any-user to read instance-family in any-tenancy"])
policies = identity_client.list_policies(
    compartment_id=policy_model.compartment_id, name=policy_model.name).data
policy = policies.pop() if len(policies) else identity_client.create_policy(policy_model).data
repeat_until_success(lambda: wait_until(identity_client, identity_client.get_policy(policy.id), 'lifecycle_state', 'ACTIVE'))
print("✅  Created Endorse Policy ...")

# Skip or Creating bin2bin compartment
print("🌼  Creating Compartment ...", end="\r")
compartment_model = identity.models.CreateCompartmentDetails(
    compartment_id= oci_config.get("tenancy"), name="bin2bin",
    description="Compartment for deploying bin2bin related resources")
compartments = identity_client.list_compartments(
    compartment_id=compartment_model.compartment_id, name=compartment_model.name).data
compartment = compartments.pop() if len(compartments) else identity_client.create_compartment(compartment_model).data
repeat_until_success(lambda: wait_until(identity_client, identity_client.get_compartment(compartment.id), 'lifecycle_state', 'ACTIVE'))
print("✅  Created Compartment ...")

# Skip or Create default vitual cloud network
print("🌼  Creating Virtual Cloud Network ...", end="\r")
vcn_model = core.models.CreateVcnDetails(
    compartment_id= compartment.id, cidr_block="10.0.0.0/16", display_name="default")
vcns = network_client.list_vcns(
    compartment_id=vcn_model.compartment_id, display_name=vcn_model.display_name).data
vcn = vcns.pop() if len(vcns) else network_client.create_vcn(vcn_model).data
repeat_until_success(lambda: wait_until(network_client, network_client.get_vcn(vcn.id), 'lifecycle_state', 'AVAILABLE'))
print("✅  Created Virtual Cloud Network ...")

# Skip or Create default security rules for virtual machine
print("🌼  Creating Security Rules ...", end="\r")
egress_security_rules = [
    {'isStateless': False, 'protocol': 'all', 'destination': '0.0.0.0/0', 'destinationType': 'CIDR_BLOCK'}]
ingress_security_rules = [
    {'isStateless': False, 'protocol': '6', 'source': '0.0.0.0/0', 'sourceType': 'CIDR_BLOCK', 'tcpOptions': {'destinationPortRange': {'max': 22, 'min': 22}}},
    {'isStateless': False, 'protocol': '6', 'source': '0.0.0.0/0', 'sourceType': 'CIDR_BLOCK', 'tcpOptions': {'destinationPortRange': {'max': 443, 'min': 443}}},
    {'isStateless': False, 'protocol': '17', 'source': '0.0.0.0/0', 'sourceType': 'CIDR_BLOCK', 'udpOptions': {'destinationPortRange': {'max': 51820, 'min': 51820}}}]
security_list_model = core.models.CreateSecurityListDetails(
    egress_security_rules=egress_security_rules, compartment_id=compartment.id,
    vcn_id=vcn.id, display_name="default", ingress_security_rules=ingress_security_rules)
security_lists = network_client.list_security_lists(
    compartment_id=security_list_model.compartment_id, 
    vcn_id=security_list_model.vcn_id, display_name=security_list_model.display_name).data
security_list = security_lists.pop() if len(security_lists) else network_client.create_security_list(security_list_model).data
repeat_until_success(lambda: wait_until(network_client, network_client.get_security_list(security_list.id), 'lifecycle_state', 'AVAILABLE'))
print("✅  Created Security Rules ...")

# Skip or Create default internet gateway for virtual machine
print("🌼  Creating Internet Gateway ...", end="\r")
internet_gateway_model = core.models.CreateInternetGatewayDetails(
    display_name= "default", is_enabled= True, compartment_id=compartment.id, vcn_id= vcn.id)
internet_gateways = network_client.list_internet_gateways(
    compartment_id=internet_gateway_model.compartment_id, 
    vcn_id=internet_gateway_model.vcn_id, 
    display_name=internet_gateway_model.display_name).data
internet_gateway = internet_gateways.pop() if len(internet_gateways) else network_client.create_internet_gateway(internet_gateway_model).data
repeat_until_success(lambda: wait_until(network_client, network_client.get_internet_gateway(internet_gateway.id), 'lifecycle_state', 'AVAILABLE'))
print("✅  Created Internet Gateway ...")

# Skip or Create default route table for default internet gateway
print("🌼  Creating Route Table ...", end="\r")
route_table_model = core.models.CreateRouteTableDetails(
    display_name="default", vcn_id=vcn.id, compartment_id=compartment.id,
    route_rules=[{"cidrBlock": "0.0.0.0/0", "networkEntityId": internet_gateway.id}])
route_tables = network_client.list_route_tables(
    compartment_id=route_table_model.compartment_id, 
    vcn_id=route_table_model.vcn_id, display_name=route_table_model.display_name).data
route_table = route_tables.pop() if len(route_tables) else network_client.create_route_table(route_table_model).data
repeat_until_success(lambda: wait_until(network_client, network_client.get_route_table(route_table.id), 'lifecycle_state', 'AVAILABLE'))
print("✅  Created Route Table ...")

# Skip or Create default subnet
print("🌼  Creating Subnet ...", end="\r")
subnet_model = core.models.CreateSubnetDetails(
    display_name="default", cidr_block="10.0.0.0/24", route_table_id=route_table.id, 
    security_list_ids=[security_list.id], vcn_id=vcn.id, compartment_id=compartment.id)
subnets = network_client.list_subnets(
    compartment_id=subnet_model.compartment_id, 
    vcn_id=subnet_model.vcn_id, display_name=subnet_model.display_name).data
subnet = subnets.pop() if len(subnets) else network_client.create_subnet(subnet_model).data
repeat_until_success(lambda: wait_until(network_client, network_client.get_subnet(subnet.id), 'lifecycle_state', 'AVAILABLE'))
print("✅  Created Subnet ...")

# Get default availability zone for free instance
print("🌼  Fetching Availability Domain ...", end="\r")
availability_domains: List[identity.models.AvailabilityDomain] = identity_client.list_availability_domains(compartment_id=oci_config.get("tenancy")).data
for availability_domain in availability_domains:
    shapes: List[core.models.Shape] = compute_client.list_shapes(oci_config.get("tenancy"), availability_domain = availability_domain.name).data
    if len([x for x in shapes if x.shape == "VM.Standard.E2.1.Micro"]): 
        print("✅  Fetched Availability Domain ...")
        break

# Switch clients to home region
print("🌼  Fetching OS image ...", end="\r")
COMPARMENT_OCID = "ocid1.compartment.oc1..aaaaaaaakjio6ufxj7mjifujudmsyonjwv7eagvusxqa4c4vtge43jzcgwlq"
os_images = compute_client.list_images(COMPARMENT_OCID, operating_system="Canonical Ubuntu").data
os_images = sorted(os_images, key=lambda x:x.time_created)
os_image: core.models.Image = [x for x in os_images if x.compartment_id == COMPARMENT_OCID].pop()
print("✅  Fetched OS image ...", end="\r")

# Skip or Create virtual machine based on the configuration
print("🌼  Creating Machine ...", end="\r")
cloud_init = CLOUD_INIT_TEMPLATE.replace("{ssh_public_key}", public_key)
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
print("✅  Created Machine ...")

# Wait for 60 seconds untill all services like SSH, wireguard, etc.. comes up
print("🌼  Waiting for services ...", end="\r"); sleep(60)

# Get public ipv4 for the created virtual machine
print("🌼  Fetching Machine IP Address ...", end="\r")
vnic: List[core.models.VnicAttachment] = compute_client.list_vnic_attachments(compartment_id=compartment.id, instance_id=instance.id).data
public_ip = network_client.get_vnic(vnic_id=vnic[0].vnic_id).data.public_ip
print("✅  Fetched Machine IP Address ...")

# Update the machine's public ip back to bin2bin
print("🌼  Updating Machine IP Address ...", end="\r")
put(f"{BASE_API_URL}/custom/put_machine_public_ip", json = {"public_ip": public_ip}, headers=auth_headers)
print("✅  Updated Machine IP Address ...")