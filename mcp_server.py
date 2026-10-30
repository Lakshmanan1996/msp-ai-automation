import base64
import json
import time

import boto3
from mcp.server.mcpserver import MCPServer

from device_resolver import DeviceResolver


mcp = MCPServer("MSP-Investigator")

REGION = "ap-south-2"

device_resolver = DeviceResolver()


def get_target(customer, site, machine):
    """
    Resolve the machine against the dynamically
    discovered AWS inventory.
    """

    device_resolver.reload()

    result = device_resolver.resolve(machine)

    if not result.get("resolved"):
        raise RuntimeError(
            f"Device resolution failed: {result.get('reason')}"
        )

    return result


def get_aws_client(region):
    """
    Create AWS SSM client for the required region.
    """

    return boto3.client(
        "ssm",
        region_name=region
    )


def run_aws_ssm(target, command, attempts=60):
    """
    Execute an approved PowerShell command
    on the resolved AWS EC2 instance.
    """

    provider = target["classification"]["provider"]
    device_type = target["classification"]["device_type"]

    if provider.upper() != "AWS":
        raise RuntimeError(
            f"AWS adapter received unsupported provider: {provider}"
        )

    aws_info = target["access"]["aws"]

    instance_id = aws_info.get("instance_id")
    region = aws_info.get("region") or REGION

    if not instance_id:
        raise RuntimeError(
            "AWS instance_id is missing for resolved device."
        )

    ssm = get_aws_client(region)

    response = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunPowerShellScript",
        Parameters={
            "commands": [command]
        }
    )

    command_id = response["Command"]["CommandId"]

    for _ in range(attempts):

        time.sleep(2)

        result = ssm.get_command_invocation(
            CommandId=command_id,
            InstanceId=instance_id
        )

        status = result["Status"]

        if status in [
            "Success",
            "Failed",
            "Cancelled",
            "TimedOut"
        ]:
            return result

    raise TimeoutError(
        f"SSM command timed out for {instance_id}"
    )


ALLOWED_CHECKS = {

    "hostname":
        "hostname",

    "network":
        (
            "Get-NetIPConfiguration; "
            "Test-Connection 10.0.0.1 -Count 2"
        ),

    "full_investigation":
        (
            "Get-Content "
            "'C:\\MSP-Automation\\investigation-result.json' "
            "-Raw"
        ),
}


@mcp.tool()
def resolve_asset(
    customer: str,
    site: str,
    machine: str
) -> str:
    """
    Resolve a device without performing investigation.
    """

    try:

        target = get_target(
            customer,
            site,
            machine
        )

        return json.dumps(
            target,
            indent=2
        )

    except Exception as e:

        return json.dumps(
            {
                "resolved": False,
                "error": str(e)
            },
            indent=2
        )


@mcp.tool()
def run_investigation_check(
    customer: str,
    site: str,
    machine: str,
    check_name: str
) -> str:
    """
    Execute an approved read-only investigation check
    on the dynamically resolved device.
    """

    if check_name not in ALLOWED_CHECKS:

        return (
            f"ERROR: Check '{check_name}' "
            f"is not approved."
        )

    try:

        target = get_target(
            customer,
            site,
            machine
        )

        provider = target["classification"]["provider"]

        if provider.upper() != "AWS":

            return json.dumps(
                {
                    "Status": "Unsupported",
                    "Reason":
                        f"Provider '{provider}' "
                        "does not have an adapter yet."
                },
                indent=2
            )

        result = run_aws_ssm(
            target,
            ALLOWED_CHECKS[check_name],
            attempts=15
        )

        return (
            f"Customer: {customer}\n"
            f"Site: {site}\n"
            f"Machine: {machine}\n"
            f"Provider: {provider}\n"
            f"Check: {check_name}\n"
            f"Status: {result['Status']}\n"
            f"Output:\n"
            f"{result.get('StandardOutputContent', '')}\n"
            f"Error:\n"
            f"{result.get('StandardErrorContent', '')}"
        )

    except Exception as e:

        return (
            f"ERROR during investigation:\n{e}"
        )


@mcp.tool()
def run_investigation(
    machine: str,
    customer: str,
    site: str,
    service_level: str,
    alert_time: str
) -> str:
    """
    Resolve the device dynamically, write the alert,
    execute the approved investigation script,
    and return investigation-result.json.
    """

    try:

        target = get_target(
            customer,
            site,
            machine
        )

        provider = target["classification"]["provider"]
        device_type = target["classification"]["device_type"]

        resolved_service_level = (
            target["service"]["noc_service_level"]
        )

        effective_service_level = (
            resolved_service_level
            or service_level
        )

        if provider.upper() != "AWS":

            return json.dumps(
                {
                    "Status": "Unsupported",
                    "Reason":
                        f"Provider '{provider}' "
                        "does not have an adapter yet.",
                    "Customer": customer,
                    "Site": site,
                    "Machine": machine
                },
                indent=2
            )

        alert_text = (
            f"Machine: {machine}\n"
            f"Customer: {customer}\n"
            f"Site: {site}\n"
            f"NOCServiceLevel: "
            f"{effective_service_level}\n"
            f"AlertSource: Zammad ticket\n"
            f"AlertType: Server Offline\n"
            f"Status: Offline\n"
            f"AlertTime: {alert_time}\n"
            f"Severity: Critical\n"
        )

        b64 = base64.b64encode(
            alert_text.encode()
        ).decode()

        command = (
            "$ErrorActionPreference='Stop'; "

            f"$t=[Text.Encoding]::UTF8.GetString("
            f"[Convert]::FromBase64String('{b64}')"
            f"); "

            "Set-Content "
            "-Path "
            "'C:\\MSP-Automation\\datto-offline-alert.txt' "
            "-Value $t; "

            "Remove-Item "
            "'C:\\MSP-Automation\\investigation-result.json' "
            "-ErrorAction SilentlyContinue; "

            "& "
            "'C:\\MSP-Automation\\automated-investigation-v3.ps1' "
            "*> $null; "

            "Get-Content "
            "'C:\\MSP-Automation\\investigation-result.json' "
            "-Raw"
        )

        result = run_aws_ssm(
            target,
            command,
            attempts=60
        )

        if result["Status"] != "Success":

            return json.dumps(
                {
                    "Status": result["Status"],
                    "Error":
                        result.get(
                            "StandardErrorContent",
                            ""
                        )
                },
                indent=2
            )

        return result.get(
            "StandardOutputContent",
            ""
        )

    except Exception as e:

        return json.dumps(
            {
                "Status": "ERROR",
                "Error": str(e)
            },
            indent=2
        )


if __name__ == "__main__":

    mcp.run("stdio")
