from argparse import ArgumentParser
from oci import identity, core
from oci import config, wait_until
from os import system
from requests import get, delete
system('clear')
print("=" * 30 + "\n😃  Virtual Machine Deletion 😃\n" + "=" * 30 + "\n")

BASE_API_URL = "https://vmkbqkse7k.execute-api.us-east-1.amazonaws.com"

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

# Fetch Compartment
print("🌼  Fetching Compartment ...", end="\r")
compartment = identity_client.list_compartments(compartment_id=oci_config.get("tenancy"), name="bin2bin").data[0]
print("✅  Fetched Compartment ...")

# Delete virtual machine
print("🌼  Deleting Machine ...", end="\r")
instance = compute_client.list_instances(compartment_id=compartment.id, display_name=machine_config["machine_id"]).data[0]
compute_client.terminate_instance(instance.id, preserve_boot_volume=False).data
wait_until(compute_client, compute_client.get_instance(instance.id), 'lifecycle_state', 'TERMINATED')
print("✅  Deleted Machine ...")

print("🌼  Updating Backend ...", end="\r")
delete(f"{BASE_API_URL}/custom/machine", headers=auth_headers)
print("✅  Updated Backend ...")

print("\n😃  Machine Deleted Successfully 😃\n")
