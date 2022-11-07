from os import cpu_count
from json import dumps
from shutil import disk_usage

cpu_info = open("/proc/cpuinfo", "r").read()
cpu_name = cpu_info.split("model name")[1] \
    .split(":")[1].split("\n")[0].strip()
os_info = open("/etc/os-release", "r").read()
os_name = os_info.split("PRETTY_NAME")[1] \
    .split('"')[1].split('"')[0].strip()
mem_info = open("/proc/meminfo", "r").read()
total_mem = mem_info.split("MemTotal")[1] \
    .split(":")[1].strip().split(" ")[0].strip()
total_swap = mem_info.split("SwapTotal")[1] \
    .split(":")[1].strip().split(" ")[0].strip()

print(dumps({
    "swap": int(total_swap), "cpu_model": cpu_name,
    "os": os_name, "disk": int(disk_usage("/")[0]),
    "cpu_count": cpu_count(), "memory": int(total_mem),
}, indent=4))