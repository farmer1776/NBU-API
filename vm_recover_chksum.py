#!/usr/bin/env python3

import argparse
import getpass
import sys
import requests
import time
import hashlib
import os
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from datetime import datetime, timedelta, timezone

# -------------------------
# Argument parsing (JSON driven)
# -------------------------

import json

parser = argparse.ArgumentParser(
    description="NetBackup 11.1 agentless VM file restore (guestfs)"
)

parser.add_argument(
    "--config",
    required=True,
    help="Path to JSON configuration file"
)

args = parser.parse_args()

# Load JSON config
try:
    with open(args.config, "r") as f:
        config = json.load(f)
except Exception as e:
    print(f"ERROR: Failed to read config file: {e}")
    sys.exit(1)

# Map config values
master = config.get("master")
username = config.get("username")
password = config.get("password")

vm_name = config.get("vm_name")
vm_username = config.get("vm_username")
vm_password = config.get("vm_password")

source_files = config.get("files")
destination = config.get("destination")

if not source_files or not isinstance(source_files, list):
    fatal("Config must include 'files' as a list of file paths")

if len(source_files) == 0:
    fatal("At least one file must be specified in 'files'")

if len(source_files) > 8:
    fatal("Maximum of 8 files allowed in 'files'")

no_check_certificate = config.get("no_check_certificate", False)
backup_days_back = config.get("backup_days_back", 30)

# Validate required fields
required_fields = {
    "master": master,
    "username": username,
    "vm_name": vm_name,
    "vm_username": vm_username,
    "files": source_files,
    "destination": destination,
}

missing = [k for k, v in required_fields.items() if not v]
if missing:
    print(f"ERROR: Missing required configuration values: {missing}")
    sys.exit(1)

# Secure password prompts if omitted
if not password:
    password = getpass.getpass("NetBackup password: ")

if not vm_password:
    vm_password = getpass.getpass("VM password: ")

if no_check_certificate:
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# -------------------------
# Constants
# -------------------------

API_VERSION = "12.0"
# API_VERSION = "14.0" # for NBU 11.1
BASE_URL = f"https://{master}/netbackup"

HEADERS_BASE = {
    "Content-Type": f"application/vnd.netbackup+json;version={API_VERSION}",
    "Accept": f"application/vnd.netbackup+json;version={API_VERSION}",
}

VERIFY_SSL = not no_check_certificate

# -------------------------
# Helper functions
# -------------------------

def fatal(msg):
    print(f"ERROR: {msg}")
    sys.exit(1)


def nb_post(url, headers, payload):
    resp = requests.post(url, headers=headers, json=payload, verify=VERIFY_SSL)
    if resp.status_code not in (200, 201):
        fatal(f"POST {url} failed ({resp.status_code}): {resp.text}")
    return resp.json()


def nb_get(url, headers, params=None):
    resp = requests.get(url, headers=headers, params=params, verify=VERIFY_SSL)
    if resp.status_code != 200:
        fatal(f"GET {url} failed ({resp.status_code}): {resp.text}")
    return resp.json()

# -------------------------
# MD5 Checksum Verification
# -------------------------

def calculate_md5(file_path, chunk_size=8192):
    """
    Calculate the MD5 checksum of a file.
    Reads the file in chunks to handle large files efficiently.
    """
    md5 = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(chunk_size):
                md5.update(chunk)
    except Exception as e:
        fatal(f"Failed to read file for MD5 calculation: {file_path} ({e})")
    return md5.hexdigest()

def verify_md5_checksums(source_files, destination_dir):
    """
    Verifies MD5 checksums of restored files.
    Assumes NetBackup appends '_restored' before the file extension.
    """
    print("\nStarting MD5 checksum verification...\n")

    for src_path in source_files:
        base_name = os.path.basename(src_path)
        name, ext = os.path.splitext(base_name)
        restored_name = f"{name}_restored{ext}"
        restored_path = os.path.join(destination_dir, restored_name)

        if not os.path.exists(restored_path):
            print(f"  WARNING: Restored file not found: {restored_path}")
            continue

        md5_value = calculate_md5(restored_path)
        print(f"  Verified: {restored_path}")
        print(f"    MD5: {md5_value}")

    print("\nMD5 verification completed.\n")


# -------------------------
# Authenticate
# -------------------------

print("Authenticating with NetBackup...")

login_payload = {
    "userName": username,
    "password": password,
}


login_resp = nb_post(
    f"{BASE_URL}/login",
    headers=HEADERS_BASE,
    payload=login_payload,
)

jwt = login_resp.get("token")
if not jwt:
    fatal("JWT token not found in login response")

HEADERS_AUTH = {
    **HEADERS_BASE,
    "Authorization": jwt,
}

print("JWT acquired")


# -------------------------
# Discover VM asset (VMware assets payload / UUID-based)
# -------------------------

print(f"Discovering VM asset '{vm_name}'...")

assets_resp = nb_get(
    f"{BASE_URL}/asset-service/workloads/vmware/assets",
    headers=HEADERS_AUTH,
    params={
        "page[offset]": 0,
        "page[limit]": 100,
        "page[disable]": "true",
    },
)

matching_assets = []

for asset in assets_resp.get("data", []):
    attrs = asset.get("attributes", {})
    common = attrs.get("commonAssetAttributes", {})
    display_name = common.get("displayName")

    if display_name == vm_name:
        matching_assets.append(asset)

if not matching_assets:
    fatal(f"No VM found with exact displayName '{vm_name}'")

if len(matching_assets) > 1:
    fatal(
        f"Multiple VMs found with name '{vm_name}'. "
        f"Please disambiguate using UUID."
    )

asset = matching_assets[0]
attrs = asset["attributes"]

# Required attributes
required_fields = [
    "uuid",
    "instanceUuid",
    "vCenter",
    "host",
    "datastore",
]

for field in required_fields:
    if field not in attrs:
        fatal(f"Missing required asset attribute: {field}")

# Primary identifiers
vm_uuid = attrs["uuid"]
instance_uuid = attrs["instanceUuid"]
vcenter = attrs["vCenter"]
esxi_server = attrs["host"]

catalog_client = attrs.get("hostName")
if not catalog_client:
    fatal("Missing hostName attribute — cannot determine catalog client")


datastores = attrs.get("datastore", [])
if not datastores:
    fatal("No datastore information found for VM")

datastore = datastores[0].get("datastoreName")
if not datastore:
    fatal("Datastore name missing in asset")

print("VM asset located:")
print(f"  VM UUID:       {vm_uuid}")
print(f"  Instance UUID: {instance_uuid}")
print(f"  vCenter:       {vcenter}")
print(f"  ESXi:          {esxi_server}")
print(f"  Datastore:     {datastore}")
print(f"  Catalog Client: {catalog_client}")

if not instance_uuid or not vm_uuid:
    fatal("Asset missing UUID or instanceUuid — cannot proceed safely")

# -------------------------
# Pre-recovery check
# -------------------------

print("Running pre-recovery check...")

precheck_payload = {
    "data": {
        "type": "vmAgentlessFilePreRecoveryCheckRequest",
        "attributes": {
            "recoveryOptions": {
                "recoveryHost": master,
                "vCenter": vcenter,
                "esxiServer": esxi_server,
                "instanceUuid": instance_uuid,
                "datastore": datastore,
                "vmUsername": vm_username,
                "vmPassword": vm_password,
                "stagingLocation": "/recovery",
                "sizeKB": 64,
                "restrictedRestoreMode": False,

            }
        },
    }
}

precheck_resp = nb_post(
    f"{BASE_URL}/recovery/workloads/vmware/scenarios/guestfs-agentless/pre-recovery-check",
    headers=HEADERS_AUTH,
    payload=precheck_payload,
)

failed = []
for item in precheck_resp.get("data", []):
    name = item["attributes"].get("name", "UNKNOWN")
    result = item["attributes"].get("result", "UNKNOWN")
    print(f"  {name}: {result}")
    if result.lower() == "fail":
        failed.append(name)

if failed:
    fatal(f"Pre-recovery check failed: {failed}")

print("Pre-recovery check passed")

# ISO 8601 date filter

def generate_backup_time_filter(days_back=30):
    """
    Generate ISO 8601 UTC date range filter for backupTime.
    Format: backupTime ge 'YYYY-MM-DDTHH:MM:SSZ' and backupTime le 'YYYY-MM-DDTHH:MM:SSZ'
    """
    now = datetime.now(timezone.utc)
    past = now - timedelta(days=days_back)

    ge_date = past.strftime("%Y-%m-%dT%H:%M:%SZ")
    le_date = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    return (
        f"backupTime ge '{ge_date}' and "
        f"backupTime le '{le_date}'"
    )


print("Generating recovery point date filter (last 30 days)...")
backup_time_filter = generate_backup_time_filter(backup_days_back)
print(f"Using filter: {backup_time_filter}")

# -------------------------
# Start recovery - do the thing
# -------------------------

print("Starting recovery job...")

recovery_start_time = time.time()

vm_files_payload = []

for file_path in source_files:
    vm_files_payload.append({
        "source": file_path,
        "destination": destination,
    })

recovery_payload = {
    "data": {
        "type": "vmAgentlessFileRecoveryRequest",
        "attributes": {
            "recoveryPoint": {
                "client": catalog_client,
                "filter": backup_time_filter,
            },
            "recoveryObject": {
                "vmFiles": vm_files_payload,
                "alternateLocationDirectory": destination,
                "flattenDirectoryStructure": True,
                "appendString": "_restored",
                "vmRecoveryDestination": {
                    "recoveryHost": master,
                    "vCenter": vcenter,
                    "esxiServer": esxi_server,
                    "instanceUuid": instance_uuid,
                    "datastore": datastore,
                    "transportMode": "san:hotadd:nbd:nbdssl",
                    "vmUsername": vm_username,
                    "vmPassword": vm_password,
                    "stagingLocation": "/recovery",
                },
            },
            "recoveryOptions": {
                "restrictedRestoreMode": False,
                "overwriteExistingFiles": True,
                "restrictMountPoints": True,
                "renameHardLinks": True,
                "renameSoftLinks": True,
                "cleanFileRestore": True,
            },
        },
    }
}

recovery_resp = nb_post(
    f"{BASE_URL}/recovery/workloads/vmware/scenarios/guestfs-agentless/recover",
    headers=HEADERS_AUTH,
    payload=recovery_payload,
)

job_id = recovery_resp.get("data", {}).get("id")
if not job_id:
    fatal("Job ID not returned from recovery request")

print(f"Recovery job started (Job ID: {job_id})")


job_registered_time = None
first_transfer_time = None
job_end_time = None
first_byte_recorded = False

# -------------------------
# Direct Job Polling
# -------------------------

print("Tracking restore job...")

restore_job_id = job_id
timeout_seconds = 7200
poll_interval = 20
start_time = time.time()


while True:

    if time.time() - start_time > timeout_seconds:
        fatal("Timed out waiting for restore job completion")

    url = f"{BASE_URL}/admin/jobs/{restore_job_id}"
    resp = requests.get(url, headers=HEADERS_AUTH, verify=VERIFY_SSL)

    # Job not yet registered
    if resp.status_code == 404:
        print("Waiting for job to register in Activity Monitor...")
        time.sleep(poll_interval)
        continue
    else:
        if job_registered_time is None:
            job_registered_time = time.time()

    # Real error
    if resp.status_code != 200:
        fatal(f"Job polling failed ({resp.status_code}): {resp.text}")

    job_resp = resp.json()

    # Defensive parsing
    if "data" not in job_resp or "attributes" not in job_resp["data"]:
        print("Job response not fully populated yet, retrying...")
        time.sleep(poll_interval)
        continue

    attrs = job_resp["data"]["attributes"]

    state = attrs.get("state")
    status = attrs.get("status")
    percent = attrs.get("percentComplete", 0)
    kb = attrs.get("kilobytesTransferred", 0)
    rate = attrs.get("transferRate", 0)

    # Capture first byte time
    if kb > 0 and not first_byte_recorded:
        first_transfer_time = time.time()
        first_byte_recorded = True

    print(
        f"  Job {restore_job_id} | "
        f"State={state} Status={status} "
        f"Progress={percent}% "
        f"KB={kb} Rate={rate} KB/s"
    )

    # Properly indented termination block
    if state in ("DONE", "FAILED", "CANCELLED"):
        job_end_time = time.time()
        break

    time.sleep(poll_interval)

# -------------------------
# Final Result Handling + RTO Metrics
# -------------------------

if not job_end_time:
    job_end_time = time.time()

total_rto_sec = job_end_time - recovery_start_time
total_rto_min = total_rto_sec / 60

registration_delay_sec = (
    job_registered_time - recovery_start_time
    if job_registered_time else 0
)
registration_delay_min = registration_delay_sec / 60

transfer_duration_sec = (
    job_end_time - first_transfer_time
    if first_transfer_time else 0
)
transfer_duration_min = transfer_duration_sec / 60

total_mb = kb / 1024
effective_rate = (
    total_mb / transfer_duration_sec if transfer_duration_sec > 0 else 0
)


# -------------------------
# MD5 Verification (after restore)
# -------------------------

if state == "DONE" and status == 0:
    print("Restore completed successfully")

    # Call MD5 verification
    verify_md5_checksums(source_files, destination)
else:
    fatal(f"Restore failed (state={state}, status={status})")


print("\n========== RTO METRICS ==========")
print(f"Total Recovery Time (RTO): {total_rto_min:.2f} minutes")
print(f"Job Registration Delay: {registration_delay_min:.2f} minutes")

if first_transfer_time:
    time_to_first_byte_min = (first_transfer_time - recovery_start_time) / 60
    print(f"Time to First Byte: {time_to_first_byte_min:.2f} minutes")
    print(f"Active Transfer Duration: {transfer_duration_min:.2f} minutes")
    print(f"Total Data Restored: {total_mb:.2f} MB")
    print(f"Effective Throughput: {effective_rate:.2f} MB/sec")

print("=================================\n")
