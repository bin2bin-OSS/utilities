from argparse import ArgumentParser
from base64 import b64encode
from os import system
from time import sleep
from requests import get, put
from oci import identity, core
from oci import config, wait_until

system('clear')
print("=" * 30 + "\n😃  Virtual Machine Setup 😃\n" + "=" * 30 + "\n")

BASE_API_URL = "https://vmkbqkse7k.execute-api.us-east-1.amazonaws.com"
DESCRIPTION = {"description": "Created Automatically by bin2bin"}
CLOUD_INIT_TEMPLATE = """
#cloud-config

disable_root: false
package_update: true

swap:
  filename: /swapfile
  size: "auto"
  maxsize: 4294967296

users:
  - name: root
    lock_passwd: true
    ssh_authorized_keys:
      - {ssh_public_key}

runcmd:
  - echo "Running run commands from cloud init user data ..."
  - echo "PermitRootLogin prohibit-password" >> /etc/ssh/sshd_config
  - systemctl restart ssh
  - echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf && sysctl -p
  - apt-get update
  - apt-get remove -y unattended-upgrades
  - apt-get -y install podman wireguard net-tools 
  - apt-get -y install haproxy iptables-persistent psmisc
  - mkdir -p /etc/wireguard && wg genkey > /etc/wireguard/dummy.key
  - echo "[Interface]" > /etc/wireguard/wg0.conf
  - echo "PrivateKey = $(cat /etc/wireguard/dummy.key)" >> /etc/wireguard/wg0.conf
  - echo "Address = 10.10.0.1/32" >> /etc/wireguard/wg0.conf
  - echo "ListenPort = 51820" >> /etc/wireguard/wg0.conf
  - systemctl enable --now wg-quick@wg0.service
  - iptables -I INPUT -p udp -m multiport --dport 53,51820 -j ACCEPT
  - iptables -I INPUT -p tcp -m multiport --dport 53,443,8080 -j ACCEPT
  - export NTWKIF=$(route -n | awk '$1 == "0.0.0.0" {print $8}')
  - iptables -I FORWARD -d 10.10.0.0/24 -i $NTWKIF -o wg0 -j ACCEPT
  - iptables -I FORWARD -s 10.10.0.0/24 -i wg0 -o $NTWKIF -j ACCEPT
  - iptables -I POSTROUTING -t nat -s 10.10.0.0/24 -o $NTWKIF -j MASQUERADE
  - iptables-save > /etc/iptables/rules.v4
  - ip6tables-save > /etc/iptables/rules.v6
  - echo "" >> /etc/haproxy/haproxy.cfg
  - echo "frontend generic_frontend" >> /etc/haproxy/haproxy.cfg
  - echo "    bind :443 ssl crt /bin2bin_app.cert" >> /etc/haproxy/haproxy.cfg
  - echo "    option forwardfor" >> /etc/haproxy/haproxy.cfg
  - echo "    option http-server-close" >> /etc/haproxy/haproxy.cfg
  - echo "    use_backend %[req.hdr(Host),lower]" >> /etc/haproxy/haproxy.cfg
  - echo "" >> /etc/haproxy/haproxy.cfg
  - systemctl restart haproxy
  - mkdir -p /podman/host-mount /podman/host-mount/etc
  - ln -s /etc/passwd /podman/host-mount/etc/passwd
  - ln -s /etc/group /podman/host-mount/etc/group
  - ln -s /proc /podman/host-mount/proc
  - ln -s /sys /podman/host-mount/sys
  - ln -s /etc/os-release /podman/host-mount/etc/os-release
  - rm -rf /var/lib/{apt,dpkg,cache,log}/
  - echo "Completed run commands from cloud init user data ..."
"""


def repeat_until_success(function):
    for _ in range(60):
        try:
            return function()
        except:
            sleep(3)
    raise Exception("Error waiting")


# Fetch SSH keys of machine
print("🌼  Fetching SSH public keys ...", end="\r")
parser = ArgumentParser()
parser.add_argument('--token', type=str, required=True)
args = parser.parse_args()
auth_headers = {"Authorization": "Bearer " + args.token}
api_url = f"{BASE_API_URL}/custom/machine"
machine_config = get(api_url, headers=auth_headers).json()
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

# Skip or Creating Compartment
print("🌼  Creating Compartment ...", end="\r")
compartments = identity_client.list_compartments(compartment_id=oci_config.get("tenancy"), name="bin2bin").data
compartment_payload = {"compartmentId": oci_config.get("tenancy"), "name": "bin2bin",  **DESCRIPTION}
compartment = compartments.pop() if len(compartments) else identity_client.create_compartment(compartment_payload).data
repeat_until_success(lambda: wait_until(identity_client, identity_client.get_compartment(compartment.id), 'lifecycle_state', 'ACTIVE'))
print("✅  Created Compartment ...")

# Skip or Create Virtual Cloud Network
print("🌼  Creating Virtual Cloud Network ...", end="\r")
vcns = network_client.list_vcns(compartment_id=compartment.id, display_name="default").data
vcn_payload = {"compartmentId": compartment.id, "cidrBlock": "10.0.0.0/16", "displayName": "default"}
vcn = vcns.pop() if len(vcns) else network_client.create_vcn(vcn_payload).data
repeat_until_success(lambda: wait_until(network_client, network_client.get_vcn(vcn.id), 'lifecycle_state', 'AVAILABLE'))
print("✅  Created Virtual Cloud Network ...")

# Skip or Create default security rules for virtual machine
print("🌼  Creating Security Rules ...", end="\r")
egress_security_rules = [
    {'isStateless': False, 'protocol': 'all', 'destination': '0.0.0.0/0', 'destinationType': 'CIDR_BLOCK'}]
ingress_security_rules = [
    {'isStateless': False, 'protocol': '6', 'source': '0.0.0.0/0', 'sourceType': 'CIDR_BLOCK', 'tcpOptions': {'destinationPortRange': {'max': 22, 'min': 22}}},
    {'isStateless': False, 'protocol': '17', 'source': '0.0.0.0/0', 'sourceType': 'CIDR_BLOCK', 'udpOptions': {'destinationPortRange': {'max': 51820, 'min': 51820}}}]
security_list_payload = {"egressSecurityRules": egress_security_rules, "compartmentId": compartment.id, "vcnId": vcn.id, "displayName": "default", "ingressSecurityRules": ingress_security_rules}
security_lists = network_client.list_security_lists(compartment_id=compartment.id, vcn_id=vcn.id, display_name="default").data
security_list = security_lists.pop() if len(security_lists) else network_client.create_security_list(security_list_payload).data
repeat_until_success(lambda: wait_until(network_client, network_client.get_security_list(security_list.id), 'lifecycle_state', 'AVAILABLE'))
print("✅  Created Security Rules ...")

# Skip or Create default internet gateway for virtual machine
print("🌼  Creating Internet Gateway ...", end="\r")
internet_gateways = network_client.list_internet_gateways(compartment_id=compartment.id, vcn_id=vcn.id, display_name="default").data
internet_gateway_payload = {"displayName": "default", "isEnabled": True, "compartmentId": compartment.id, "vcnId": vcn.id}
internet_gateway = internet_gateways.pop() if len(internet_gateways) else network_client.create_internet_gateway(internet_gateway_payload).data
repeat_until_success(lambda: wait_until(network_client, network_client.get_internet_gateway(internet_gateway.id), 'lifecycle_state', 'AVAILABLE'))
print("✅  Created Internet Gateway ...")

# Skip or Create default route table for default internet gateway
print("🌼  Creating Route Table ...", end="\r")
route_tables = network_client.list_route_tables(compartment_id=compartment.id, vcn_id=vcn.id, display_name="default").data
route_table_payload = {"displayName": "default", "vcnId": vcn.id, "compartmentId": compartment.id, "routeRules": [{"cidrBlock": "0.0.0.0/0", "networkEntityId": internet_gateway.id}]}
route_table = route_tables.pop() if len(route_tables) else network_client.create_route_table(route_table_payload).data
repeat_until_success(lambda: wait_until(network_client, network_client.get_route_table(route_table.id), 'lifecycle_state', 'AVAILABLE'))
print("✅  Created Route Table ...")

# Skip or Create default subnet
print("🌼  Creating Subnet ...", end="\r")
subnets = network_client.list_subnets(compartment_id=compartment.id, vcn_id=vcn.id, display_name="default").data
subnet_payload = {"displayName": "default", "cidrBlock": "10.0.0.0/24", "routeTableId": route_table.id, "securityListIds": [security_list.id], "vcnId": vcn.id, "compartmentId": compartment.id}
subnet = subnets.pop() if len(subnets) else network_client.create_subnet(subnet_payload).data
repeat_until_success(lambda: wait_until(network_client, network_client.get_subnet(subnet.id), 'lifecycle_state', 'AVAILABLE'))
print("✅  Created Subnet ...")

# Get default availability zone for free instance
print("🌼  Fetching Availability Domain ...", end="\r")
availability_domains = identity_client.list_availability_domains(compartment_id=oci_config.get("tenancy")).data
for availability_domain in availability_domains:
    availability_domain.shapes = compute_client.list_shapes(oci_config.get("tenancy"), availability_domain=availability_domain.name).data
    availability_domain.free_shapes = [item for item in availability_domain.shapes if item.shape == "VM.Standard.E2.1.Micro"]

free_availability_domains = [item.name for item in availability_domains if len(item.free_shapes)]
availability_domain = free_availability_domains[0] if len(free_availability_domains) else availability_domain.name
print("✅  Fetched Availability Domain ...")

# Get OS images
print("🌼  Fetching OS image ...", end="\r")
os_images = compute_client.list_images(compartment.id, operating_system="Canonical Ubuntu", lifecycle_state="AVAILABLE", operating_system_version="22.04 Minimal").data
os_image = sorted(os_images, key=lambda x: x.display_name).pop()
print("✅  Fetched OS image ...", end="\r")

# Skip or Create virtual machine
print("🌼  Creating Machine ...", end="\r")
cloud_init = CLOUD_INIT_TEMPLATE.replace("{ssh_public_key}", machine_config["public_key"])
instance_payload = {
    "agent_config": {"are_all_plugins_disabled": True},
    "availabilityDomain": availability_domain,
    "compartmentId": compartment.id,
    "shape": "VM.Standard.E2.1.Micro",
    "metadata": {
        'ssh_authorized_keys': machine_config["public_key"],
        'user_data': b64encode(cloud_init.encode()).decode()
    },
    "displayName": machine_config["machine_id"],
    "sourceDetails": {
        "imageId": os_image.id, "sourceType": "image",
        "bootVolumeSizeInGBs": 100, "bootVolumeVpusPerGB": 120
    },
    "createVnicDetails": {"subnetId": subnet.id, "assignPublicIp": True},
}
instances = compute_client.list_instances(compartment_id=compartment.id, display_name=machine_config["machine_id"]).data
instance = instances.pop() if len(instances) else compute_client.launch_instance(instance_payload).data
repeat_until_success(lambda: wait_until(compute_client, compute_client.get_instance(instance.id), 'lifecycle_state', 'RUNNING'))
print("✅  Created Machine ...")

# Wait for 60 seconds untill all services like SSH, wireguard, etc.. comes up
print("🌼  Waiting for services ...", end="\r")
sleep(60)

# Get public ipv4 for the created virtual machine
print("🌼  Fetching Machine IP Address ...", end="\r")
vnic = compute_client.list_vnic_attachments(compartment_id=compartment.id, instance_id=instance.id).data
public_ip = network_client.get_vnic(vnic_id=vnic[0].vnic_id).data.public_ip
print("✅  Fetched Machine IP Address ...")

# Update the machine's public ip back to bin2bin
print("🌼  Updating Machine IP Address ...", end="\r")
payload = {
    "operating_system": os_image.operating_system + " " + os_image.operating_system_version,
    "availability_domain": availability_domain, "tenant_ocid": oci_config.get("tenancy"),
    "public_ip": public_ip, "disk": "100 gb", "cpu": "AMD based 1/8 OCPU",
    "compartment_ocid": compartment.id, "region": oci_config["region"], "ram": "1 gb"}
put(f"{BASE_API_URL}/custom/machine", json={"config": payload}, headers=auth_headers)
print("✅  Updated Machine IP Address ...")

print("\n😃  Please go back to the bin2bin application to view machine status 😃\n")
