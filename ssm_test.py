import boto3
import time

REGION = "ap-south-2"
INSTANCE_ID = "i-091ea53a092bba846"

ssm = boto3.client("ssm", region_name=REGION)

print("Sending command to Windows server...")

response = ssm.send_command(
    InstanceIds=[INSTANCE_ID],
    DocumentName="AWS-RunPowerShellScript",
    Parameters={
        "commands": ["hostname"]
    }
)

command_id = response["Command"]["CommandId"]

print(f"Command ID: {command_id}")
print("Waiting for Windows server...")

for _ in range(12):
    time.sleep(5)

    result = ssm.get_command_invocation(
        CommandId=command_id,
        InstanceId=INSTANCE_ID
    )

    status = result["Status"]
    print(f"Status: {status}")

    if status in ["Success", "Failed", "Cancelled", "TimedOut"]:
        print("\n===== COMMAND RESULT =====")
        print(result.get("StandardOutputContent", ""))
        print("\n===== ERROR =====")
        print(result.get("StandardErrorContent", ""))
        break
