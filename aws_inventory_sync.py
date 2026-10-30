import boto3
import json
from datetime import datetime, timezone

REGION = "ap-south-2"

ROLE_ARN = (
    "arn:aws:iam::985658740862:"
    "role/MSP-AI-EC2-Inventory-Role"
)

OUTPUT_FILE = "/opt/msp-ai/aws_inventory.json"

# EC2 tags read as the "ITGlue" record of each machine.
# Add these tags to each EC2 instance in the AWS console:
#   Name            -> machine name used in the alert (e.g. Test server)
#   Customer        -> Demo-Customer
#   Site            -> NOC-LA
#   NOCServiceLevel -> DNOC.SRV.Manage   or   DNOC.Monitor
#   MachineType     -> virtual           (optional, default virtual)
#   Hypervisor      -> aws_ec2           (optional)


def assume_inventory_role():
    sts = boto3.client("sts", region_name=REGION)

    response = sts.assume_role(
        RoleArn=ROLE_ARN,
        RoleSessionName="MSPAIDynamicInventory"
    )

    credentials = response["Credentials"]

    return boto3.client(
        "ec2",
        region_name=REGION,
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    )


def discover_instances(ec2):
    instances = []

    paginator = ec2.get_paginator("describe_instances")

    for page in paginator.paginate():

        for reservation in page["Reservations"]:

            for instance in reservation["Instances"]:

                tags = {
                    tag["Key"]: tag["Value"]
                    for tag in instance.get("Tags", [])
                }

                name = tags.get("Name")

                if not name:
                    name = instance["InstanceId"]

                instances.append({
                    "machine": name,
                    "instance_id": instance["InstanceId"],
                    "provider": "AWS",
                    "device_type": "EC2",
                    "region": REGION,
                    "private_ip": instance.get("PrivateIpAddress"),
                    "private_dns": instance.get("PrivateDnsName"),
                    "state": instance["State"]["Name"],
                    "instance_type": instance.get("InstanceType"),
                    "availability_zone": instance.get(
                        "Placement", {}
                    ).get("AvailabilityZone"),
                    "platform": instance.get("Platform"),

                    # --- ITGlue-style record, taken from EC2 tags ---
                    "customer": tags.get("Customer"),
                    "site": tags.get("Site"),
                    "noc_service_level": tags.get("NOCServiceLevel"),
                    "machine_type": tags.get("MachineType", "virtual"),
                    "hypervisor": tags.get("Hypervisor", "aws_ec2"),
                    "vendor": tags.get("Vendor"),

                    "discovered_at": datetime.now(timezone.utc).isoformat()
                })

    return instances


def main():

    print("========================================")
    print(" AWS DYNAMIC INVENTORY DISCOVERY")
    print("========================================")

    print("\nAssuming inventory role...")

    ec2 = assume_inventory_role()

    print("Inventory role assumed successfully.")

    print("\nDiscovering EC2 instances...")

    instances = discover_instances(ec2)

    with open(OUTPUT_FILE, "w") as f:
        json.dump(instances, f, indent=2)

    print(f"\nDiscovered {len(instances)} EC2 instance(s).")

    print(f"Inventory written to:")
    print(OUTPUT_FILE)

    print("\nDiscovered machines:")

    for instance in instances:
        print(
            f"- {instance['machine']} | "
            f"{instance['instance_id']} | "
            f"{instance['private_ip']} | "
            f"{instance['state']} | "
            f"{instance['customer']} | "
            f"{instance['site']}"
        )


if __name__ == "__main__":
    main()
