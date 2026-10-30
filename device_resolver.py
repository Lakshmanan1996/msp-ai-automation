import json
import os


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

INVENTORY_FILE = os.path.join(
    BASE_DIR,
    "aws_inventory.json"
)


class DeviceResolver:
    """
    Generic MSP/NOC device resolver.

    Resolves an asset using multiple possible identifiers:

      - machine name
      - hostname
      - instance ID
      - private IP
      - DNS name

    This module does NOT:
      - run investigations
      - execute AWS commands
      - execute PowerShell
      - connect to iDRAC/iLO
      - make AI decisions

    Its responsibility is only:

        Alert identity
              ↓
        Correct asset
              ↓
        Normalized asset information
    """

    def __init__(self, inventory_file=INVENTORY_FILE):

        self.inventory_file = inventory_file
        self.devices = self._load_inventory()

    # ==========================================================
    # INVENTORY
    # ==========================================================

    def _load_inventory(self):

        if not os.path.exists(self.inventory_file):

            raise FileNotFoundError(
                f"Inventory not found: {self.inventory_file}"
            )

        with open(
            self.inventory_file,
            "r",
            encoding="utf-8"
        ) as f:

            data = json.load(f)

        if not isinstance(data, list):

            raise ValueError(
                "Inventory must contain a JSON list."
            )

        return data

    def reload(self):

        self.devices = self._load_inventory()

    # ==========================================================
    # IDENTIFIER MATCHING
    # ==========================================================

    def _normalize(self, value):

        return str(
            value or ""
        ).strip().lower()

    def _find_machine(self, machine):

        requested = self._normalize(
            machine
        )

        matches = []

        for device in self.devices:

            identifiers = [

                device.get(
                    "machine"
                ),

                device.get(
                    "hostname"
                ),

                device.get(
                    "instance_id"
                ),

                device.get(
                    "private_ip"
                ),

                device.get(
                    "private_dns"
                )
            ]

            for identifier in identifiers:

                if (
                    self._normalize(
                        identifier
                    )
                    ==
                    requested
                ):

                    matches.append(device)

                    break

        return matches

    # ==========================================================
    # MANAGEMENT CAPABILITIES
    # ==========================================================

    def _build_management(
        self,
        device,
        provider,
        device_type
    ):

        provider = str(
            provider or ""
        ).upper()

        device_type = str(
            device_type or ""
        ).upper()

        # ------------------------------------------------------
        # AWS SSM
        # ------------------------------------------------------

        aws_applicable = (
            provider == "AWS"
        )

        aws_available = (
            aws_applicable
            and
            bool(
                device.get(
                    "instance_id"
                )
            )
        )

        # ------------------------------------------------------
        # Dell iDRAC
        # ------------------------------------------------------

        vendor = str(
            device.get(
                "vendor",
                ""
            )
        ).lower()

        normalized_type = str(
            device.get(
                "device_type",
                ""
            )
        ).lower()

        physical_types = (
            "physical",
            "server",
            "physical_server"
        )

        idrac_applicable = (
            vendor == "dell"
            and
            normalized_type in physical_types
        )

        idrac_available = bool(
            device.get(
                "idrac_available",
                False
            )
        )

        # ------------------------------------------------------
        # HPE iLO
        # ------------------------------------------------------

        ilo_applicable = (
            vendor in (
                "hpe",
                "hp"
            )
            and
            normalized_type in physical_types
        )

        ilo_available = bool(
            device.get(
                "ilo_available",
                False
            )
        )

        # ------------------------------------------------------
        # VMware
        # ------------------------------------------------------

        vmware_applicable = (

            provider.lower()
            in (
                "vmware",
                "esxi",
                "vcenter"
            )

            or

            device_type.lower()
            in (
                "vmware_vm",
                "virtual_machine"
            )
        )

        vmware_available = bool(
            device.get(
                "vmware_available",
                False
            )
        )

        # ------------------------------------------------------
        # OS Agent
        # ------------------------------------------------------

        os_agent_available = bool(
            device.get(
                "os_agent_available",
                False
            )
        )

        return {

            "aws_ssm": {

                "applicable":
                    aws_applicable,

                "available":
                    aws_available,

                "instance_id":
                    device.get(
                        "instance_id"
                    ),

                "region":
                    device.get(
                        "region"
                    )
            },

            "idrac": {

                "applicable":
                    idrac_applicable,

                "available":
                    (
                        idrac_available
                        if idrac_applicable
                        else False
                    )
            },

            "ilo": {

                "applicable":
                    ilo_applicable,

                "available":
                    (
                        ilo_available
                        if ilo_applicable
                        else False
                    )
            },

            "vmware": {

                "applicable":
                    vmware_applicable,

                "available":
                    (
                        vmware_available
                        if vmware_applicable
                        else False
                    )
            },

            "os_agent": {

                "applicable":
                    True,

                "available":
                    os_agent_available
            }
        }

    # ==========================================================
    # RESOLVE DEVICE
    # ==========================================================

    def resolve(
        self,
        machine,
        customer=None,
        site=None,
        service_level=None
    ):

        machine = str(
            machine or ""
        ).strip()

        if not machine:

            return {
                "resolved": False,
                "reason": "Machine name is required."
            }

        # ------------------------------------------------------
        # Search using all supported identifiers
        # ------------------------------------------------------

        matches = self._find_machine(
            machine
        )

        # ------------------------------------------------------
        # Device not found
        # ------------------------------------------------------

        if len(matches) == 0:

            return {

                "resolved": False,

                "reason":
                    "Device not found in inventory.",

                "machine":
                    machine
            }

        # ------------------------------------------------------
        # Multiple devices found
        # ------------------------------------------------------

        if len(matches) > 1:

            return {

                "resolved": False,

                "reason":
                    "Multiple matching devices found.",

                "machine":
                    machine,

                "matches": [
                    device.get(
                        "instance_id",
                        device.get(
                            "machine"
                        )
                    )
                    for device in matches
                ]
            }

        # ------------------------------------------------------
        # Correct asset found
        # ------------------------------------------------------

        device = matches[0]

        provider = device.get(
            "provider",
            "UNKNOWN"
        )

        device_type = device.get(
            "device_type",
            "UNKNOWN"
        )

        # ------------------------------------------------------
        # Determine physical / virtual
        # ------------------------------------------------------

        machine_type = device.get(
            "machine_type"
        )

        if not machine_type:

            normalized_type = str(
                device_type
            ).lower()

            if normalized_type in (
                "physical",
                "server",
                "physical_server"
            ):

                machine_type = "physical"

            elif normalized_type in (
                "vm",
                "vmware_vm",
                "virtual_machine",
                "ec2"
            ):

                machine_type = "virtual"

            else:

                machine_type = "unknown"

        # ------------------------------------------------------
        # Management capabilities
        # ------------------------------------------------------

        management = self._build_management(

            device,

            provider,

            device_type
        )

        # ------------------------------------------------------
        # Normalized asset
        # ------------------------------------------------------

        result = {

            "resolved": True,

            # ==================================================
            # GENERIC ASSET
            # ==================================================

            "asset": {

                "customer":
                    customer,

                "site":
                    site,

                "machine":
                    device.get(
                        "machine"
                    ),

                "hostname":
                    device.get(
                        "hostname"
                    ),

                "provider":
                    provider,

                "device_type":
                    device_type,

                "machine_type":
                    machine_type,

                "vendor":
                    device.get(
                        "vendor"
                    ),

                "model":
                    device.get(
                        "model"
                    ),

                "os":
                    device.get(
                        "platform",
                        device.get(
                            "os"
                        )
                    )
            },

            # ==================================================
            # CLASSIFICATION
            # ==================================================

            "classification": {

                "provider":
                    provider,

                "device_type":
                    device_type,

                "machine_type":
                    machine_type,

                "machine_role":
                    device.get(
                        "machine_role",
                        "Server"
                    ),

                "environment":
                    device.get(
                        "environment",
                        "Unknown"
                    ),

                "os":
                    device.get(
                        "platform",
                        device.get(
                            "os"
                        )
                    ),

                "hypervisor":
                    device.get(
                        "hypervisor"
                    )
            },

            # ==================================================
            # MANAGEMENT
            # ==================================================

            "management":
                management,

            # ==================================================
            # SERVICE
            # ==================================================

            "service": {

                "noc_service_level":
                    (
                        service_level
                        or
                        device.get(
                            "noc_service_level"
                        )
                        or
                        "DNOC.SRV.Manage"
                    ),

                "remediation_allowed":
                    device.get(
                        "remediation_allowed",
                        True
                    )
            },

            # ==================================================
            # ACCESS
            # ==================================================

            "access": {

                "access_path":
                    device.get(
                        "access_path"
                    ),

                "infrastructure_id":
                    device.get(
                        "instance_id",
                        device.get(
                            "infrastructure_id"
                        )
                    ),

                "aws": {

                    "instance_id":
                        device.get(
                            "instance_id"
                        ),

                    "region":
                        device.get(
                            "region"
                        )
                },

                "vmware": {

                    "host":
                        device.get(
                            "esxi_host"
                        ),

                    "cluster":
                        device.get(
                            "cluster"
                        )
                },

                "physical": {

                    "idrac":
                        device.get(
                            "idrac"
                        ),

                    "ilo":
                        device.get(
                            "ilo"
                        )
                }
            },

            # ==================================================
            # INFRASTRUCTURE
            # ==================================================

            "infrastructure": {

                "provider":
                    provider,

                "region":
                    device.get(
                        "region"
                    ),

                "state":
                    device.get(
                        "state"
                    ),

                "instance_type":
                    device.get(
                        "instance_type"
                    ),

                "availability_zone":
                    device.get(
                        "availability_zone"
                    ),

                "host":
                    device.get(
                        "esxi_host"
                    ),

                "cluster":
                    device.get(
                        "cluster"
                    )
            },

            # ==================================================
            # NETWORK
            # ==================================================

            "network": {

                "private_ip":
                    device.get(
                        "private_ip"
                    ),

                "private_dns":
                    device.get(
                        "private_dns"
                    )
            },

            # ==================================================
            # COMPATIBILITY FIELDS
            # ==================================================

            "machine":
                device.get(
                    "machine"
                ),

            "customer":
                customer,

            "site":
                site,

            "ip":
                device.get(
                    "private_ip"
                ),

            "type":
                machine_type,

            "hypervisor":
                device.get(
                    "hypervisor"
                ),

            "region":
                device.get(
                    "region"
                ),

            "instance_id":
                device.get(
                    "instance_id"
                ),

            "state":
                device.get(
                    "state"
                ),

            "maintenance":
                device.get(
                    "maintenance",
                    []
                ),

            # ==================================================
            # ORIGINAL INVENTORY RECORD
            # ==================================================

            "raw":
                device
        }

        return result


# ==============================================================
# CONVENIENCE FUNCTION
# ==============================================================

def resolve_device(
    machine,
    customer=None,
    site=None,
    service_level=None
):

    resolver = DeviceResolver()

    return resolver.resolve(

        machine=machine,

        customer=customer,

        site=site,

        service_level=service_level
    )


# ==============================================================
# DIRECT TEST
# ==============================================================

if __name__ == "__main__":

    resolver = DeviceResolver()

    print()
    print("========================================")
    print(" GENERIC MSP DEVICE RESOLVER TEST")
    print("========================================")

    test_names = [

        "Test server",

        "EC2AMAZ-JEANI4A"
    ]

    for machine in test_names:

        print()
        print("----------------------------------------")
        print(
            f"Testing: {machine}"
        )
        print("----------------------------------------")

        result = resolver.resolve(

            machine=machine,

            customer="Demo-Customer",

            site="NOC-LA",

            service_level="DNOC.SRV.Manage"
        )

        print(
            json.dumps(
                result,
                indent=2
            )
        )
