"""
MSP AI NOC AUTOMATION - ai_mcp_orchestrator_v1.5.py

Built on v12 (online / false-positive flow is unchanged). New in v1.5:
  * OFFLINE ticket note in the real NOC template (Hello Team ... Next Action Required by MSP)
  * Infrastructure checks for MANAGE customers, chosen by machine type:
        Physical Dell  -> iDRAC (Redfish)      Physical HP -> iLO (Redfish)
        VM on AWS      -> EC2 state + status checks
        VM on VMware   -> ESXi host / vCenter (host state + VM power + VMware Tools)
        VM on Hyper-V  -> Hyper-V host guest machines (Get-VM, cluster nodes)
  * Infra credentials come from CyberArk (CCP) when the customer provided them; if not,
    the note says the hardware check was not possible (some customers give no credentials)
  * Deterministic root cause from infra facts (AI still decides CLOSE/RECHECK/HOLD/ESCALATE)
  * Lab simulation file (lab_infra.json) so iDRAC/iLO/ESXi/Hyper-V results can be demoed
    without real hardware

Flow per Zammad offline-alert ticket:
  1. Read alert (zammad_client)            2. Resolve device (device_resolver, EC2 tags)
  3. Ping from an ONLINE probe via SSM (never from the GCP VM)
  4. Service level decides what is allowed:
       MONITOR : ping from the probe only. No login, no infra checks, no fixes.
       MANAGE  : ping + infra check + read-only troubleshooting via SSM
  5. Ollama decides CLOSE / RECHECK / HOLD / ESCALATE; code guardrails override unsafe answers
  6. Write the NOC note (online template or offline template) and update the ticket

Design rule: code collects facts, AI only interprets them. A tool failure is TOOL_ERROR
(internal "automation-error" note) and is never reported as "machine offline".

Network assumption: the automation server must have a network path to the customer's
iDRAC/iLO, ESXi/vCenter and Hyper-V hosts (site VPN or a customer-side collector).

Environment variables (v12 ones still apply: MSP_AWS_ROLE_ARN, MSP_AWS_PROFILE,
PROBE_INSTANCE_ID, PROBE_REGION, PROBE_OS, SYNC_ON_ALERT, MONITOR_AUTOCLOSE,
DATTO_AGENT_CHECK, AUTO_REMEDIATE). New:
  INFRA_CHECKS          1 = run infrastructure checks for Manage customers (default 1)
  CYBERARK_CCP_URL      e.g. https://cyberark.example.com  (empty = use lab credentials)
  CYBERARK_APP_ID       CCP application id
  CYBERARK_SAFE_TEMPLATE    default "{customer}"
  CYBERARK_OBJECT_TEMPLATE  default "{machine}-{kind}"   kind = idrac|ilo|vmware|hyperv
  LAB_CREDS_FILE        lab only: {"demo-customer": {"idrac": {"user": "..", "password": ".."}}}
  OOB_USER / OOB_PASS   last-resort shared lab credentials
  INFRA_SIM_FILE        lab only: {"<machine>": {"platform": "Dell iDRAC", "checked": true,
                        "power_state": "Off", "console": "health=Critical",
                        "verdict": "POWERED_OFF", "findings": []}}

Optional inventory fields (aws_inventory.json / lab_devices.json) used by the checks:
  public_ip / external_ip  -> external ping line
  oob_ip                   -> iDRAC / iLO address (or access.physical.idrac / .ilo)
  vcenter, esxi_host, vm_name   -> VMware VMs
  hyperv_host              -> Hyper-V VMs (hypervisor = hyperv | failover_cluster)

Python packages: requests, boto3, mcp.  Optional: pyvmomi (VMware), pywinrm (Hyper-V).
"""
import asyncio
import call_service
import contextlib
import datetime as dt
import io
import ipaddress
import json
import os
import socket
import time
from concurrent.futures import ThreadPoolExecutor

import requests
import urllib3
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

import zammad_client as z
from device_resolver import DeviceResolver

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ------------------------------------------------------------------ config
POLL_SECONDS = 30
HOLD_HOURS = 1
MAX_RECHECKS = 2
RECHECK_SECONDS = 60
MCP_SERVER = "/opt/msp-ai/mcp_server.py"
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/chat")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:7b")
OOB_USER = os.getenv("OOB_USER", "")
OOB_PASS = os.getenv("OOB_PASS", "")

PROBE_INSTANCE_ID = os.getenv("PROBE_INSTANCE_ID", "")
PROBE_REGION = os.getenv("PROBE_REGION", "ap-south-2")
PROBE_OS = os.getenv("PROBE_OS", "windows").lower()
SYNC_ON_ALERT = os.getenv("SYNC_ON_ALERT", "1") == "1"
MONITOR_AUTOCLOSE = os.getenv("MONITOR_AUTOCLOSE", "1") == "1"
DATTO_AGENT_CHECK = os.getenv("DATTO_AGENT_CHECK", "0") == "1"
AUTO_REMEDIATE = os.getenv("AUTO_REMEDIATE", "0") == "1"

INFRA_CHECKS = os.getenv("INFRA_CHECKS", "1") == "1"
CYBERARK_CCP_URL = os.getenv("CYBERARK_CCP_URL", "")
CYBERARK_APP_ID = os.getenv("CYBERARK_APP_ID", "")
CYBERARK_SAFE_TEMPLATE = os.getenv("CYBERARK_SAFE_TEMPLATE", "{customer}")
CYBERARK_OBJECT_TEMPLATE = os.getenv("CYBERARK_OBJECT_TEMPLATE", "{machine}-{kind}")
LAB_CREDS_FILE = os.getenv("LAB_CREDS_FILE", "/opt/msp-ai/lab_credentials.json")
INFRA_SIM_FILE = os.getenv("INFRA_SIM_FILE", "/opt/msp-ai/lab_infra.json")


def _norm(v):
    return str(v or "").strip().lower()


# ------------------------------------------------------------- inventory
def refresh_inventory():
    """Re-discover EC2 instances (aws_inventory_sync) so state/tags are current."""
    if not SYNC_ON_ALERT:
        return
    try:
        import aws_inventory_sync
        with contextlib.redirect_stdout(io.StringIO()):
            aws_inventory_sync.main()
    except Exception as e:
        print(f"Inventory sync skipped: {e}")


def resolve_device(alert):
    """Returns (resolved_dict, all_devices). Customer + site break ties when the same
    machine name exists more than once."""
    resolver = DeviceResolver()
    cands = resolver._find_machine(alert["Machine"])
    if len(cands) > 1:
        narrowed = [d for d in cands
                    if _norm(d.get("customer")) == _norm(alert["Customer"])
                    and _norm(d.get("site")) == _norm(alert["Site"])]
        if len(narrowed) == 1:
            cands = narrowed
    key = cands[0]["instance_id"] if len(cands) == 1 else alert["Machine"]
    res = resolver.resolve(key, customer=alert["Customer"], site=alert["Site"],
                           service_level=alert["NOCServiceLevel"])
    if not res.get("machine_type"):
        raw = res.get("raw") or {}
        aws = (res.get("access") or {}).get("aws") or {}
        if aws.get("instance_id") or _norm(raw.get("device_type")) == "ec2":
            res["machine_type"] = "virtual"      # an EC2 instance is always a VM
    return res, resolver.devices


def active_maintenance(res, alert_time):
    try:
        t = dt.datetime.strptime(alert_time, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    for w in res.get("maintenance") or []:
        s = dt.datetime.strptime(w["start"], "%Y-%m-%d %H:%M:%S")
        e = dt.datetime.strptime(w["end"], "%Y-%m-%d %H:%M:%S")
        if s <= t <= e:
            return w
    return None


# ------------------------------------------------------------- AWS session
_CRED_CACHE = {}


def aws_client(service, region):
    """boto3 client. If MSP_AWS_ROLE_ARN is set, assume that role (credentials cached until
    5 minutes before expiry) so we do not depend on the server's default credentials
    (the SSM hybrid identity mi-... has no SendCommand on the targets)."""
    import boto3
    base = boto3.Session(profile_name=os.getenv("MSP_AWS_PROFILE") or None)
    role = os.getenv("MSP_AWS_ROLE_ARN")
    if not role:
        return base.client(service, region_name=region)
    c = _CRED_CACHE.get(role)
    soon = dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5)
    if not c or c["Expiration"] <= soon:
        c = base.client("sts", region_name=region).assume_role(
            RoleArn=role, RoleSessionName="MSPAIOrchestrator")["Credentials"]
        _CRED_CACHE[role] = c
    return boto3.client(service, region_name=region,
                        aws_access_key_id=c["AccessKeyId"],
                        aws_secret_access_key=c["SecretAccessKey"],
                        aws_session_token=c["SessionToken"])


# ------------------------------------------------------------- SSM helper
def ssm_run(instance_id, region, commands, doc="AWS-RunPowerShellScript", wait=60):
    """Run commands on an instance via SSM.
    Returns {"state": "DONE", "status", "out", "err"}
         or {"state": "NOT_CONNECTED", "detail"}  (SSM agent not answering = a FACT)
         or {"state": "TOOL_ERROR", "detail"}     (our fault: permissions, timeout ...)
    """
    from botocore.exceptions import ClientError
    try:
        ssm = aws_client("ssm", region)
        sent = ssm.send_command(InstanceIds=[instance_id], DocumentName=doc,
                                Parameters={"commands": commands},
                                TimeoutSeconds=max(wait, 30))
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "InvalidInstanceId":
            return {"state": "NOT_CONNECTED",
                    "detail": "SSM agent on the machine is not responding"}
        return {"state": "TOOL_ERROR", "detail": f"{code}: {e.response['Error']['Message']}"}
    except Exception as e:
        return {"state": "TOOL_ERROR", "detail": str(e)}

    cid = sent["Command"]["CommandId"]
    inv = None
    for _ in range(max(wait // 2, 1)):
        time.sleep(2)
        try:
            inv = ssm.get_command_invocation(CommandId=cid, InstanceId=instance_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvocationDoesNotExist":
                continue
            return {"state": "TOOL_ERROR", "detail": str(e)}
        if inv["Status"] not in ("Pending", "InProgress", "Delayed"):
            break
    else:
        return {"state": "TOOL_ERROR", "detail": "SSM command timed out"}
    return {"state": "DONE", "status": inv["Status"],
            "out": (inv.get("StandardOutputContent") or "").strip(),
            "err": (inv.get("StandardErrorContent") or "").strip()}


# ------------------------------------------------------------- ping probe
def _summary_line(out):
    for line in out.splitlines():
        low = line.lower()
        if "packets" in low and ("sent" in low or "transmitted" in low):
            return line.strip()
    lines = [l for l in out.splitlines() if l.strip()]
    return lines[-1].strip() if lines else ""


def probe_ping_ip(ip, target_instance_id=None):
    """Ping <ip> from the online PROBE machine (SSM).
    Returns REACHABLE / UNREACHABLE / SKIPPED / TOOL_ERROR. 'Destination host unreachable'
    replies do not count: only replies containing TTL= do."""
    if not ip:
        return {"status": "TOOL_ERROR", "detail": "no IP in inventory"}
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {"status": "TOOL_ERROR", "detail": f"invalid IP in inventory: {ip}"}
    if not PROBE_INSTANCE_ID:
        return {"status": "TOOL_ERROR",
                "detail": "PROBE_INSTANCE_ID is not set (need an online machine to ping from)"}
    if target_instance_id and target_instance_id == PROBE_INSTANCE_ID:
        return {"status": "SKIPPED",
                "detail": "target is the probe machine; ICMP from itself is not meaningful"}

    if PROBE_OS == "windows":
        doc, cmd = "AWS-RunPowerShellScript", f"ping -n 4 -w 2000 {ip}"
    else:
        doc, cmd = "AWS-RunShellScript", f"ping -c 4 -W 2 {ip}"
    r = ssm_run(PROBE_INSTANCE_ID, PROBE_REGION, [cmd], doc, wait=60)
    if r["state"] != "DONE":
        return {"status": "TOOL_ERROR", "detail": f"probe unavailable: {r['detail']}"}
    if r["status"] not in ("Success", "Failed") or not r["out"]:
        return {"status": "TOOL_ERROR",
                "detail": f"probe ping failed to run ({r['status']}): {r['err'][:150]}"}
    got_reply = any("ttl=" in l.lower() for l in r["out"].splitlines())
    return {"status": "REACHABLE" if got_reply else "UNREACHABLE",
            "detail": _summary_line(r["out"]), "raw": r["out"]}


def peers_status(devices, res, site):
    """Ping up to 5 other devices of the same site (in parallel) to spot a site-wide outage."""
    me = res.get("instance_id")
    peers = [d for d in devices
             if _norm(d.get("site")) == _norm(site) and d.get("instance_id") not in (me, PROBE_INSTANCE_ID)
             and d.get("private_ip")][:5]
    if not peers:
        return {"total": 0, "offline": 0, "offline_names": []}
    with ThreadPoolExecutor(max_workers=len(peers)) as pool:
        results = list(pool.map(
            lambda d: probe_ping_ip(d["private_ip"], d.get("instance_id"))["status"], peers))
    offline = [d["machine"] for d, s in zip(peers, results) if s == "UNREACHABLE"]
    return {"total": len(peers), "offline": len(offline), "offline_names": offline}


# ------------------------------------------------------ platform labels
def platform_label(res):
    mt = res.get("machine_type")
    prov = str((res.get("classification") or {}).get("provider") or "").upper()
    hv = _norm(res.get("hypervisor"))
    vendor = _norm((res.get("asset") or {}).get("vendor"))
    if mt == "virtual":
        if prov == "AWS":
            return "AWS EC2"
        if hv in ("vmware", "esxi", "vcenter"):
            return "VMware"
        if hv == "hyperv":
            return "Hyper-V"
        if hv == "failover_cluster":
            return "Hyper-V cluster"
        return "virtual"
    if mt == "physical":
        return {"dell": "Dell", "hp": "HP", "hpe": "HP"}.get(vendor, "physical")
    return ""


def system_line(res):
    mt, label = res.get("machine_type"), platform_label(res)
    if mt == "virtual":
        return f"We have found that this is a virtual machine ({label})."
    if mt == "physical":
        return f"We have found that this is a physical machine ({label})."
    return "Machine type could not be determined."


# ------------------------------------------------------- credentials
def get_credentials(alert, kind):
    """(user, password) for kind = idrac | ilo | vmware | hyperv, or None when the customer
    did not provide credentials. CyberArk CCP first; lab file / shared lab account otherwise.
    Secrets are never logged and never written to the ticket."""
    if CYBERARK_CCP_URL:
        try:
            r = requests.get(
                f"{CYBERARK_CCP_URL}/AIMWebService/api/Accounts", timeout=10,
                params={"AppID": CYBERARK_APP_ID,
                        "Safe": CYBERARK_SAFE_TEMPLATE.format(customer=alert["Customer"]),
                        "Object": CYBERARK_OBJECT_TEMPLATE.format(
                            machine=alert["Machine"], kind=kind)})
            if r.ok:
                j = r.json()
                return j["UserName"], j["Content"]
        except Exception:
            pass
        return None
    try:
        with open(LAB_CREDS_FILE) as f:
            c = (json.load(f).get(_norm(alert["Customer"])) or {}).get(kind)
        if c:
            return c["user"], c["password"]
    except (OSError, ValueError, KeyError):
        pass
    if OOB_USER and OOB_PASS:
        return OOB_USER, OOB_PASS
    return None


def infra_sim(machine):
    """Lab only: canned infra result for a machine (see INFRA_SIM_FILE)."""
    try:
        with open(INFRA_SIM_FILE) as f:
            return json.load(f).get(machine)
    except (OSError, ValueError):
        return None


def tcp_open(host, port, timeout=5):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


# ------------------------------------------------------ infrastructure checks
# Every check returns a dict: platform, checked, power_state, console, findings[], verdict,
# detail/error. verdict is one of:
#   POWERED_OFF | HOST_DOWN | UNHEALTHY | GUEST_UNRESPONSIVE | OOB_UNREACHABLE | STARTING | HEALTHY
def check_ec2(res):
    aws = res["access"]["aws"]
    try:
        ec2 = aws_client("ec2", aws.get("region") or PROBE_REGION)
        st = ec2.describe_instance_status(InstanceIds=[aws["instance_id"]],
                                          IncludeAllInstances=True)["InstanceStatuses"][0]
        state = st["InstanceState"]["Name"]
        s_sys, s_inst = st["SystemStatus"]["Status"], st["InstanceStatus"]["Status"]
        if state != "running":
            verdict = "POWERED_OFF"
        elif "impaired" in (s_sys, s_inst):
            verdict = "UNHEALTHY"
        elif s_sys == "ok" and s_inst == "ok":
            verdict = "HEALTHY"
        else:
            verdict = "STARTING"
        return {"platform": "AWS EC2", "checked": True, "power_state": state,
                "console": f"system={s_sys}, instance={s_inst}", "findings": [],
                "verdict": verdict}
    except Exception as e:
        return {"platform": "AWS EC2", "checked": False, "error": str(e)}


def aws_online_evidence(res):
    """Facts from AWS itself, independent of ICMP: EC2 state + status checks + SSM agent
    heartbeat (lab equivalent of 'Datto agent checking in')."""
    aws = (res.get("access") or {}).get("aws") or {}
    iid = aws.get("instance_id") or res.get("instance_id")
    region = aws.get("region") or PROBE_REGION
    ev = {"online": False, "state": None, "status_checks": None,
          "ssm_ping": None, "errors": []}
    if not iid:
        ev["errors"].append("no EC2 instance id in inventory")
        return ev
    checks_ok = False
    try:
        st = aws_client("ec2", region).describe_instance_status(
            InstanceIds=[iid], IncludeAllInstances=True)["InstanceStatuses"][0]
        ev["state"] = st["InstanceState"]["Name"]
        s_sys, s_inst = st["SystemStatus"]["Status"], st["InstanceStatus"]["Status"]
        ev["status_checks"] = f"system={s_sys}, instance={s_inst}"
        checks_ok = s_sys == "ok" and s_inst == "ok"
    except Exception as e:
        ev["errors"].append(f"EC2 status: {e}")
    try:
        info = aws_client("ssm", region).describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [iid]}])["InstanceInformationList"]
        ev["ssm_ping"] = info[0]["PingStatus"] if info else "NotRegistered"
    except Exception as e:
        ev["errors"].append(f"SSM heartbeat: {e}")      # unknown, not a machine fact
    ev["online"] = (ev["state"] == "running" and checks_ok
                    and ev["ssm_ping"] not in ("ConnectionLost", "Inactive", "NotRegistered"))
    return ev


def aws_public(ev):
    return None if not ev else {k: v for k, v in ev.items() if k != "errors"}


def aws_lines(ev):
    if ev and ev.get("ssm_ping"):
        return [f"- SSM/management agent heartbeat: {ev['ssm_ping']}."]
    return []


def online_root_cause(p, ev):
    if p["status"] == "REACHABLE":
        return "The machine is online and communicating normally; the alert was a false positive."
    return ("The machine is online (AWS reports it running with passed status checks and an "
            "active management agent); ICMP ping gets no reply, so the offline alert was a "
            "false positive.")


# ---- Dell iDRAC / HP iLO (Redfish) ----
REDFISH_LOGS = {
    "dell": "/redfish/v1/Managers/iDRAC.Embedded.1/LogServices/Sel/Entries",
    "hp": "/redfish/v1/Systems/1/LogServices/IML/Entries",
    "hpe": "/redfish/v1/Systems/1/LogServices/IML/Entries",
}


def redfish_query(oob_ip, creds, vendor):
    """Returns (power_state, health, last_log_entries). Dell iDRAC and HP iLO both speak
    Redfish. The log read is best effort (paths differ per generation)."""
    base = f"https://{oob_ip}"
    s = requests.Session()
    s.auth, s.verify = creds, False
    r = s.get(f"{base}/redfish/v1/Systems", timeout=10)
    r.raise_for_status()
    member = r.json()["Members"][0]["@odata.id"]
    d = s.get(base + member, timeout=10).json()
    events = []
    try:
        path = REDFISH_LOGS.get(vendor)
        if path:
            members = s.get(base + path, timeout=10).json().get("Members", [])
            members.sort(key=lambda m: m.get("Created", ""), reverse=True)
            events = [f"{m.get('Created', '')[:19]} {m.get('Message', '')}".strip()
                      for m in members[:3]]
    except Exception:
        pass
    return d.get("PowerState"), (d.get("Status") or {}).get("Health"), events


def check_physical(res, alert):
    raw = res.get("raw") or {}
    vendor = _norm((res.get("asset") or {}).get("vendor"))
    kind, label = {"dell": ("idrac", "Dell iDRAC"), "hp": ("ilo", "HP iLO"),
                   "hpe": ("ilo", "HP iLO")}.get(vendor, (None, None))
    if not label:
        return {"platform": "Other hardware", "checked": False,
                "detail": "no OOB interface; on-site physical check is needed"}
    phys = (res.get("access") or {}).get("physical") or {}
    oob = phys.get(kind) or raw.get("oob_ip")
    if not oob:
        return {"platform": label, "checked": False,
                "detail": f"no {label} address in inventory"}
    creds = get_credentials(alert, kind)
    if not creds:
        return {"platform": label, "checked": False,
                "detail": f"customer has not provided {label} credentials"}
    p = probe_ping_ip(oob)
    if p["status"] != "REACHABLE":
        return {"platform": label, "checked": False, "verdict": "OOB_UNREACHABLE",
                "detail": f"{label} {oob} is not reachable from an online machine "
                          f"in the same group ({p['status']})"}
    try:
        power, health, events = redfish_query(oob, creds, vendor)
    except Exception as e:
        return {"platform": label, "checked": False, "error": f"{label} query failed: {e}"}
    if _norm(power) == "off":
        verdict = "POWERED_OFF"
    elif _norm(health) == "critical":
        verdict = "UNHEALTHY"
    else:
        verdict = "HEALTHY"
    return {"platform": label, "checked": True, "power_state": power,
            "console": f"health={health}", "findings": events, "verdict": verdict}


# ---- VMware: ESXi host / vCenter ----
def check_vmware(res, alert):
    raw = res.get("raw") or {}
    target = raw.get("vcenter") or raw.get("esxi_host")
    vm_name = raw.get("vm_name") or alert["Machine"]
    if not target:
        return {"platform": "VMware", "checked": False,
                "detail": "no ESXi host / vCenter address in inventory"}
    creds = get_credentials(alert, "vmware")
    if not creds:
        return {"platform": "VMware", "checked": False,
                "detail": "customer has not provided ESXi/vCenter credentials"}
    if not tcp_open(target, 443):
        return {"platform": "VMware", "checked": True, "verdict": "HOST_DOWN",
                "power_state": "unknown", "console": f"{target} not responding on 443",
                "findings": []}
    try:
        import ssl
        from pyVim.connect import SmartConnect, Disconnect
        from pyVmomi import vim
    except ImportError:
        return {"platform": "VMware", "checked": False,
                "error": "pyvmomi is not installed (pip install pyvmomi)"}
    try:
        si = SmartConnect(host=target, user=creds[0], pwd=creds[1],
                          sslContext=ssl._create_unverified_context())
    except Exception as e:
        return {"platform": "VMware", "checked": False, "error": f"login to {target} failed: {e}"}
    try:
        content = si.RetrieveContent()
        view = content.viewManager.CreateContainerView(content.rootFolder,
                                                       [vim.VirtualMachine], True)
        try:
            vm = next((v for v in view.view if _norm(v.name) == _norm(vm_name)), None)
        finally:
            view.Destroy()
        if vm is None:
            return {"platform": "VMware", "checked": False,
                    "detail": f"VM '{vm_name}' not found on {target}"}
        host = vm.runtime.host
        hr = host.runtime
        host_txt = (f"host {host.name}: connection={hr.connectionState}, "
                    f"power={hr.powerState}, health={host.overallStatus}")
        vm_power = str(vm.runtime.powerState)
        tools = str(vm.guest.toolsRunningStatus)
        findings = [host_txt, f"VMware Tools: {tools}"]
        if str(hr.connectionState) != "connected" or str(hr.powerState) != "poweredOn":
            verdict = "HOST_DOWN"
        elif vm_power != "poweredOn":
            verdict = "POWERED_OFF"
        elif tools == "guestToolsNotRunning":
            verdict = "GUEST_UNRESPONSIVE"
        elif str(host.overallStatus) == "red":
            verdict = "UNHEALTHY"
        else:
            verdict = "HEALTHY"
        return {"platform": "VMware ESXi", "checked": True, "power_state": vm_power,
                "console": f"host={host.name} ({hr.connectionState})", "findings": findings,
                "verdict": verdict}
    except Exception as e:
        return {"platform": "VMware", "checked": False, "error": f"VMware query failed: {e}"}
    finally:
        Disconnect(si)


# ---- Hyper-V host: guest machines (and cluster nodes) ----
PS_HYPERV = r"""
$ErrorActionPreference='SilentlyContinue'
$vms = @(Get-VM | Select-Object Name,@{n='State';e={"$($_.State)"}},@{n='Heartbeat';e={"$($_.Heartbeat)"}})
$nodes = @(Get-ClusterNode | Select-Object Name,@{n='State';e={"$($_.State)"}})
@{vms=$vms; nodes=$nodes} | ConvertTo-Json -Compress -Depth 3
"""


def _as_list(x):
    if not x:
        return []
    return [x] if isinstance(x, dict) else list(x)


def check_hyperv(res, alert):
    raw = res.get("raw") or {}
    host = raw.get("hyperv_host")
    vm_name = raw.get("vm_name") or alert["Machine"]
    label = platform_label(res) or "Hyper-V"
    if not host:
        return {"platform": label, "checked": False,
                "detail": "no Hyper-V host address in inventory"}
    creds = get_credentials(alert, "hyperv")
    if not creds:
        return {"platform": label, "checked": False,
                "detail": "customer has not provided Hyper-V host credentials"}
    if not tcp_open(host, 5985):
        return {"platform": label, "checked": True, "verdict": "HOST_DOWN",
                "power_state": "unknown", "console": f"host {host} not responding on WinRM",
                "findings": []}
    try:
        import winrm
    except ImportError:
        return {"platform": label, "checked": False,
                "error": "pywinrm is not installed (pip install pywinrm)"}
    try:
        sess = winrm.Session(host, auth=creds, transport="ntlm",
                             operation_timeout_sec=20, read_timeout_sec=30)
        r = sess.run_ps(PS_HYPERV)
        if r.status_code != 0:
            return {"platform": label, "checked": False,
                    "error": f"Hyper-V query failed: {r.std_err.decode(errors='ignore')[:150]}"}
        data = json.loads(r.std_out.decode(errors="ignore") or "{}")
    except Exception as e:
        return {"platform": label, "checked": False, "error": f"Hyper-V query failed: {e}"}

    guests = _as_list(data.get("vms"))
    nodes = _as_list(data.get("nodes"))
    me = next((g for g in guests if _norm(g.get("Name")) == _norm(vm_name)), None)
    if me is None:
        return {"platform": label, "checked": False,
                "detail": f"guest '{vm_name}' not found on Hyper-V host {host}"}
    others_down = [g["Name"] for g in guests if g is not me and g.get("State") != "Running"]
    nodes_down = [n["Name"] for n in nodes if n.get("State") != "Up"]
    findings = [f"{len(guests)} guest machines on host {host}, {len(others_down)} other guest(s) "
                "not running" + (f": {', '.join(others_down)}" if others_down else "")]
    if nodes_down:
        findings.append(f"Cluster nodes not up: {', '.join(nodes_down)}")
    hb = str(me.get("Heartbeat"))
    if me.get("State") != "Running":
        verdict = "POWERED_OFF"
    elif hb.startswith("Error") or hb.startswith("Lost"):
        verdict = "GUEST_UNRESPONSIVE"
    elif nodes_down:
        verdict = "UNHEALTHY"
    else:
        verdict = "HEALTHY"
    return {"platform": label, "checked": True, "power_state": me.get("State"),
            "console": f"host={host}, heartbeat={hb}", "findings": findings,
            "verdict": verdict}


def platform_check(res, alert, mode):
    """STEP: VM or Physical, then branch to the right infrastructure. MONITOR customers get
    no platform checks."""
    mt = res.get("machine_type")
    mtype = {"virtual": "Virtual Machine", "physical": "Physical Machine"}.get(
        mt, "Not determined")
    label = platform_label(res) or "unknown"
    if mode == "MONITOR":
        return mtype, {"platform": label, "checked": False, "skipped": True,
                       "detail": "monitoring-only customer, no platform checks"}
    if not INFRA_CHECKS:
        return mtype, {"platform": label, "checked": False, "skipped": True,
                       "detail": "infrastructure checks disabled"}
    sim = infra_sim(alert["Machine"])
    if sim:
        sim = dict(sim)
        sim.setdefault("platform", label)
        sim.setdefault("checked", True)
        sim.setdefault("findings", [])
        return mtype, sim
    prov = str((res.get("classification") or {}).get("provider") or "").upper()
    hv = _norm(res.get("hypervisor"))
    if mt == "virtual":
        if prov == "AWS":
            return mtype, check_ec2(res)
        if hv in ("vmware", "esxi", "vcenter"):
            return mtype, check_vmware(res, alert)
        if hv in ("hyperv", "failover_cluster"):
            return mtype, check_hyperv(res, alert)
        return mtype, {"platform": label, "checked": False,
                       "detail": "no infrastructure connector for this hypervisor yet"}
    if mt == "physical":
        return mtype, check_physical(res, alert)
    return mtype, {"platform": label, "checked": False,
                   "detail": "machine type missing in inventory"}


# ----------------------------------------------- MANAGE: troubleshooting checklist
PS_TROUBLESHOOT = r"""
$ErrorActionPreference='SilentlyContinue'
"NIC=" + ((Get-NetAdapter | ForEach-Object { "$($_.Name):$($_.Status)" }) -join ';')
"IP=" + ((Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '127.*' } | ForEach-Object { $_.IPAddress }) -join ',')
$gw = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1).NextHop
"GATEWAY=$gw"
if ($gw -and $gw -ne '0.0.0.0') { "GATEWAY_PING=" + (Test-Connection $gw -Count 2 -Quiet) }
$svc = Get-Service -Name 'CagService'
if ($svc) { "DATTO_AGENT=" + $svc.Status } else { "DATTO_AGENT=NotInstalled" }
"DISK_FREE_GB=" + [math]::Round((Get-PSDrive C).Free/1GB,1)
"LASTBOOT=" + (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
"EVENTS=" + ((Get-WinEvent -FilterHashtable @{LogName='System';Id=1074,6008,41;StartTime=(Get-Date).AddHours(-24)} -MaxEvents 5 | ForEach-Object { "$($_.Id)@$($_.TimeCreated.ToString('yyyy-MM-dd HH:mm'))" }) -join ';')
"""


def _parse_kv(text):
    kv = {}
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            kv[k.strip()] = v.strip()
    return kv


def interpret_checks(kv):
    problems, info = [], []
    for nic in filter(None, kv.get("NIC", "").split(";")):
        name, _, state = nic.rpartition(":")
        if state.lower() == "disabled":
            problems.append(f"Network adapter '{name}' is disabled.")
    ips = [i for i in kv.get("IP", "").split(",") if i]
    if not ips:
        problems.append("No IPv4 address is assigned to the machine.")
    elif any(i.startswith("169.254.") for i in ips):
        problems.append("Machine has an APIPA (169.254.x.x) address - DHCP failure.")
    if kv.get("GATEWAY_PING", "").lower() == "false":
        problems.append(f"Default gateway {kv.get('GATEWAY')} is not reachable from the machine.")
    if DATTO_AGENT_CHECK and kv.get("DATTO_AGENT") != "Running":
        problems.append(f"Datto RMM agent service state: {kv.get('DATTO_AGENT', 'unknown')}.")
    try:
        if float(kv.get("DISK_FREE_GB", "999")) < 1.0:
            problems.append(f"System drive is almost full ({kv['DISK_FREE_GB']} GB free).")
    except ValueError:
        pass
    if kv.get("EVENTS"):
        info.append("Restart/shutdown events in the last 24h: " + kv["EVENTS"].replace(";", ", "))
    if kv.get("LASTBOOT"):
        info.append(f"Last boot: {kv['LASTBOOT']}")
    return problems, info


def manage_troubleshoot(res):
    """Log in (SSM) to the machine and run the read-only checklist."""
    out = {"ran": False, "problems": [], "info": [], "tool_error": None}
    aws = res["access"]["aws"]
    if str(res["classification"].get("provider")).upper() != "AWS" or not aws.get("instance_id"):
        out["info"].append("Remote login is not supported for this platform yet.")
        return out
    if _norm(res["raw"].get("platform")) != "windows":
        out["info"].append("Troubleshooting checklist is written for Windows; skipped.")
        return out

    r = ssm_run(aws["instance_id"], aws.get("region") or PROBE_REGION,
                PS_TROUBLESHOOT.strip().splitlines(), wait=60)
    if r["state"] == "NOT_CONNECTED":
        out["problems"].append("Remote login to the machine failed: its SSM/management agent "
                               "is not responding.")
        return out
    if r["state"] == "TOOL_ERROR":
        out["tool_error"] = r["detail"]
        return out
    if r["status"] != "Success":
        out["tool_error"] = f"troubleshooting script status {r['status']}: {r['err'][:150]}"
        return out

    out["ran"] = True
    kv = _parse_kv(r["out"])
    out["problems"], out["info"] = interpret_checks(kv)

    if (AUTO_REMEDIATE and res["service"].get("remediation_allowed")
            and kv.get("DATTO_AGENT") == "Stopped" and DATTO_AGENT_CHECK):
        fix = ssm_run(aws["instance_id"], aws.get("region") or PROBE_REGION,
                      ["Start-Service CagService; (Get-Service CagService).Status"], wait=30)
        if fix["state"] == "DONE":
            out["info"].append(f"Remediation attempted: started Datto agent service "
                               f"(state now: {fix['out'] or 'unknown'}).")
    return out


# ------------------------------------------------------------- MCP evidence
async def investigate(session, alert):
    """Existing MCP evidence tool (runs automated-investigation-v3.ps1). MANAGE only."""
    try:
        res = await session.call_tool("run_investigation", {
            "machine": alert["Machine"], "customer": alert["Customer"],
            "site": alert["Site"], "service_level": alert["NOCServiceLevel"],
            "alert_time": alert["AlertTime"]})
        text = "".join(c.text for c in res.content if hasattr(c, "text"))
        try:
            return json.loads(text)
        except ValueError:
            return {"raw": text[:800]}
    except Exception as e:
        return {"error": str(e)}


# ------------------------------------------------------------------- AI step
SYSTEM_PROMPT = """You are a NOC L1 analyst. Decide using ONLY the evidence JSON.
Decisions:
- CLOSE: machine answers ping from the probe (or AWS proves it online) and troubleshooting found no problems (false positive).
- RECHECK: unreachable but may be transient (only when recheck_attempts < max_rechecks and infrastructure.verdict is not POWERED_OFF / HOST_DOWN / UNHEALTHY).
- HOLD: an active maintenance window exists.
- ESCALATE: unreachable/down, problems found, site-wide outage, hardware issue, infrastructure verdict POWERED_OFF / HOST_DOWN / UNHEALTHY / GUEST_UNRESPONSIVE / OOB_UNREACHABLE, or unknown.
Never invent facts. If evidence contains tool errors, ignore them (they are not machine facts).
root_cause must be ONE short sentence in this style, based only on the evidence:
"As internal IP is not reachable; it might be VM is in powered off state."
(say "machine" instead of "VM" for physical machines; for a false positive say the machine is
online and the alert was a false positive).
Reply JSON only:
{"decision":"...","root_cause":"one sentence","actions":["..."]}"""


def ai_decide(context):
    try:
        r = requests.post(OLLAMA_URL, timeout=120, json={
            "model": OLLAMA_MODEL, "stream": False, "format": "json",
            "options": {"temperature": 0},
            "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                         {"role": "user", "content": json.dumps(context, indent=1)}]})
        out = json.loads(r.json()["message"]["content"])
        d = str(out.get("decision", "")).upper()
        if d not in ("CLOSE", "RECHECK", "HOLD", "ESCALATE"):
            raise ValueError(f"bad decision {d}")
        return d, out.get("root_cause", ""), out.get("actions", [])
    except Exception as e:
        return "ESCALATE", f"AI decision failed ({e}); manual review needed.", []


# ---------------------------------------------------------------- templates
def offline_root_cause(res, plat, peers, ai_text):
    """Root cause from FACTS first (infra verdict, site-wide outage); AI sentence only when
    the facts do not decide it."""
    noun = "VM" if res.get("machine_type") == "virtual" else "machine"
    label = plat.get("platform") or "Infrastructure"
    v = plat.get("verdict")
    if peers["total"] >= 2 and peers["offline"] == peers["total"]:
        return ("The machine and the other devices at the site are offline, possibly due to "
                "a power outage or a network failure at the site.")
    if v == "POWERED_OFF":
        return f"As internal IP is not reachable; {label} reports the {noun} is in powered off state."
    if v == "HOST_DOWN":
        return (f"As internal IP is not reachable; the host server of the {noun} is not "
                "responding, so the machine may be down because of a host failure.")
    if v == "UNHEALTHY":
        return (f"As internal IP is not reachable; {label} reports an unhealthy state "
                f"({plat.get('console')}).")
    if v == "GUEST_UNRESPONSIVE":
        return (f"The {noun} is powered on but the guest operating system is not responding; "
                "the machine may be hung.")
    if v == "OOB_UNREACHABLE":
        return (f"As internal IP is not reachable; the {label} interface is also not reachable, "
                "possibly due to a power or network issue at the site.")
    if v == "STARTING":
        return f"The {noun} is running but its status checks are still initializing (recently started)."
    if v == "HEALTHY":
        return (f"The {noun} is powered on and healthy at the infrastructure level but its internal "
                "IP is not reachable; possible OS hang, network adapter or firewall issue.")
    return (ai_text or "").strip() or (
        f"As internal IP is not reachable; it might be {noun} is in powered off state.")


NEXT_ACTIONS = {
    "POWERED_OFF": "Needs to check why the machine is powered off and power it on after "
                   "confirming there is no planned activity.",
    "HOST_DOWN": "Needs to check the status of the host server (ESXi / Hyper-V) running the machine.",
    "UNHEALTHY": "Needs to check the hardware / health alert reported by the management interface.",
    "GUEST_UNRESPONSIVE": "Needs to check the machine console, as the guest OS is not responding.",
    "OOB_UNREACHABLE": "Needs to check network connectivity to the iDRAC / iLO interface.",
}


def build_online_report(alert, res, mtype, plat, p, ts, maint, decision, root_cause, mode,
                        aws_ev=None):
    """Online / false-positive template (unchanged from v12)."""
    level = "Monitor" if mode == "MONITOR" else "Manage"
    reachable = p["status"] == "REACHABLE"
    head = (f"Affected Customer : {alert['Customer']}\n"
            f"Affected Machine : {alert['Machine']}\n"
            f"Affected Site Name: {alert['Site']}\n\n"
            f"System Info:\n"
            f"- Verified the NOC Service Level, it is {level}.\n"
            f"- {system_line(res)}\n\n")
    if reachable:
        acts = ["- Ping check from an online machine in the same group succeeded."]
    elif p["status"] == "SKIPPED":
        acts = ["- Ping check from the probe was not applicable (target is the probe machine)."]
    else:
        acts = ["- Ping (ICMP) from an online machine in the same group got no reply; "
                "ICMP may be blocked by the firewall or security group."]
    if p.get("raw"):
        acts.append(p["raw"])
    if plat.get("checked"):
        acts.append(f"- {plat['platform']} check: power state {plat.get('power_state')}, "
                    f"{plat.get('console')}")
    acts += aws_lines(aws_ev)
    if mode == "MANAGE" and ts.get("ran"):
        acts.append("- Logged in to the machine and verified network adapter, IP "
                    "configuration, gateway and disk: no issues found.")
    acts += [f"- {i}" for i in ts.get("info", [])]
    acts.append("- Maintenance window: none active at alert time.")
    return ("Hi Team,\n\n"
            "We have received a device Offline alert for the below-mentioned machine.\n\n"
            + head +
            "Action Performed:\n" + "\n".join(acts) + "\n\n"
            f"Root Cause:\n- {root_cause}\n\n"
            "Ticket Closure:\n"
            "- The offline alert was a false positive; the machine is online and "
            "communicating normally.\n"
            "- The alert is resolved and the ticket is being closed.\n\n"
            "Please let us know if you need any further assistance.")


def build_offline_report(alert, res, plat, p, ext, ts, maint, peers, mode, root_cause,
                         probe_name):
    """OFFLINE template - Hello Team ... Next Action Required by MSP."""
    level = "DNOC.Monitor" if mode == "MONITOR" else "DNOC.SRV.Manage"
    kind = {"virtual": "Virtual Machine", "physical": "Physical Machine"}.get(
        res.get("machine_type"), "Machine (type could not be determined)")
    lines = ["Hello Team,", "",
             "We have received offline alert for the below mentioned machine", "",
             f"Affected Machine: {alert['Machine']}",
             f"Affected Site: {alert['Site']}", "",
             "System Info:", "",
             f"- We have found that this is {kind}",
             f"- Machines are enrolled under Noc Service level: {level}", "",
             "Action Performed:", ""]

    # ping status lines
    if ext and ext["status"] in ("REACHABLE", "UNREACHABLE"):
        lines.append("-Ping test Status- External Ip is " +
                     ("reachable." if ext["status"] == "REACHABLE" else "not reachable."))
    lines.append("-Ping test Status- Internal Ip is " +
                 ("reachable." if p["status"] == "REACHABLE" else "not reachable."))
    # the same evidence an engineer pastes: hostname of the online machine + ping output
    lines += ["", "hostname", probe_name, f"PS C:\\> ping {res.get('ip')}", ""]
    if p.get("raw"):
        lines += [p["raw"], ""]

    # infrastructure check
    if plat.get("checked"):
        lines.append(f"-{plat['platform']} check: power state {plat.get('power_state')}, "
                     f"{plat.get('console')}")
        lines += [f"-{f}" for f in plat.get("findings", [])]
    elif not plat.get("skipped") and plat.get("detail"):
        lines.append(f"-{plat['platform']} check could not be completed: {plat['detail']}.")
    # VMs have no hardware management interface: say so explicitly
    if res.get("machine_type") == "virtual":
        vm_platform = platform_label(res) or "virtual platform"
        if plat.get("checked"):
            lines.append(f"-iDRAC/iLO check is not applicable: this is a virtual machine "
                         f"({vm_platform}), so the power state was verified from the "
                         f"{vm_platform} platform instead.")
        else:
            lines.append(f"-iDRAC/iLO check is not applicable: this is a virtual machine "
                         f"({vm_platform}).")

    if mode == "MANAGE":
        lines += [f"-{x}" for x in ts.get("problems", [])]
        lines += [f"-{x}" for x in ts.get("info", [])]
    lines.append("-Maintenance window: " +
                 (f"active until {maint['end']}." if maint else "none active at alert time."))
    if peers["total"]:
        if peers["offline"]:
            lines.append(f"-Other devices at this site are showing offline "
                         f"({peers['offline']} of {peers['total']}): "
                         f"{', '.join(peers['offline_names'])}")
        else:
            lines.append(f"-The other {peers['total']} devices checked at this site are online.")

    lines += ["", "Root Cause:", "", f"- {root_cause}", "",
              "Next Action Required by MSP:", ""]
    extra = NEXT_ACTIONS.get(plat.get("verdict"))
    if extra:
        lines += [f"-{extra}", ""]
    lines += ["-Needs to check the status of the machines.", "",
              "-Needs to check if machines are up and communicating over the network.", "",
              "-Check for power Input status for the network devices.", "", "",
              "Ticket Closure:", "",
              "Verified in DRMM and found that the machine is in offline state. "]
    if peers["total"] >= 2 and peers["offline"] == peers["total"]:
        lines += ["", "All the devices checked at the site are also in offline state "]
    if mode == "MONITOR":
        lines += ["", "We are unable to verify further as this is monitoring only machine."]
    lines += ["", "Please do let us know if you need any further assistance on this."]
    return "\n".join(lines)


def build_not_enrolled_report(alert, reason):
    """Escalation template for a machine that is not enrolled in NOC inventory."""
    return (
        "Hello Team,\n\n"
        "We have received an Offline alert for the below-mentioned machine.\n\n"
        f"Affected Customer: {alert['Customer']}\n"
        f"Affected Machine: {alert['Machine']}\n"
        f"Affected Site: {alert['Site']}\n"
        f"NOC Service Level: {alert['NOCServiceLevel']}\n\n"
        "Finding:\n"
        "- The reported machine could not be found in the NOC enrolled device inventory.\n"
        "- The machine could not be mapped to an enrolled DNOC.SRV.Manage or "
        "DNOC.Monitor device.\n"
        f"- Inventory resolution result: {reason}\n\n"
        "Investigation:\n"
        "- No server-level investigation was performed because the machine could "
        "not be resolved to an enrolled NOC asset.\n"
        "- AWS/Windows investigation was not attempted for this alert.\n\n"
        "Action Taken:\n"
        "- The alert is being escalated for NOC enrollment and device mapping validation.\n"
        "- Please verify whether the reported machine should be enrolled and mapped "
        "to the appropriate NOC service level.\n\n"
        "Ticket Status:\n"
        "- Escalated for manual review.\n\n"
        "Please do let us know if you need any further assistance."
    )


# -------------------------------------------------------------- ticket flow



# -------------------------------------------------------------- ticket flow
async def process_ticket(session, ticket):
    tid, number = ticket["id"], ticket["number"]
    z.claim(tid)
    print(f"\n===== NEW ALERT: ticket #{number} =====")

    alert = z.parse_alert(z.get_ticket_body(tid))
    missing = [k for k, v in alert.items() if not v]
    if missing:
        z.add_note(tid, f"Could not read alert fields: {', '.join(missing)}. "
                        "Escalated for manual review.")
        z.add_tag(tid, "escalated")
        return

    z.add_note(tid, "Automation started: running the investigation.")
    refresh_inventory()
    res, devices = resolve_device(alert)
    if not res.get("resolved"):
        reason = res.get("reason") or "Device not found in inventory."
        report = build_not_enrolled_report(alert, reason)

        z.add_note(tid, report)
        z.add_tag(tid, "device-not-enrolled")
        z.add_tag(tid, "escalated")
        z.set_state(tid, "open")
        
        print("\n--- DEVICE NOT ENROLLED ---")
        print(report)
        print("--- DECISION: ESCALATE ---")
        return

    z.add_note(tid, "Device resolved successfully from dynamic AWS inventory.")

    # The alert's service level is the authority (the resolver only defaults to Manage)
    mode = "MONITOR" if "monitor" in alert["NOCServiceLevel"].lower() else "MANAGE"
    maint = active_maintenance(res, alert["AlertTime"])
    data = await investigate(session, alert) if mode == "MANAGE" else {}
    probe_name = next((d["machine"] for d in devices
                       if d.get("instance_id") == PROBE_INSTANCE_ID), PROBE_INSTANCE_ID)
    raw = res.get("raw") or {}
    ext_ip = raw.get("public_ip") or raw.get("external_ip")
    attempts = 0

    while True:
        p = probe_ping_ip(res.get("ip"), res.get("instance_id"))
        if p["status"] == "TOOL_ERROR":                       # automation fault, not an outage
            z.add_note(tid, f"Automation error: {p['detail']}. Escalated for manual review.")
            z.add_tag(tid, "automation-error")
            z.set_state(tid, "open")
            return

        mtype, plat = platform_check(res, alert, mode)
        if plat.get("error"):
            z.add_note(tid, f"Automation note (internal): {plat['error']}")
        ts = manage_troubleshoot(res) if mode == "MANAGE" else \
            {"ran": False, "problems": [], "info": [], "tool_error": None}
        if ts.get("tool_error"):
            z.add_note(tid, f"Automation note (internal): troubleshooting failed: {ts['tool_error']}")
        aws_ev = (aws_online_evidence(res) if mode == "MANAGE"
                  and str(res["classification"].get("provider") or "").upper() == "AWS" else None)
        if aws_ev and aws_ev["errors"]:
            z.add_note(tid, "Automation note (internal): AWS evidence incomplete: "
                            + "; ".join(aws_ev["errors"]))
        online_verified = p["status"] == "REACHABLE" or bool(aws_ev and aws_ev["online"])
        unreachable = p["status"] == "UNREACHABLE" and not online_verified
        peers = (peers_status(devices, res, alert["Site"]) if unreachable
                 else {"total": 0, "offline": 0, "offline_names": []})
        ext = probe_ping_ip(ext_ip) if (ext_ip and unreachable) else None
        if ext and ext["status"] == "TOOL_ERROR":
            ext = None

        context = {"mode": mode, "machine_type": mtype,
                   "ping_from_probe": {"status": p["status"], "detail": p["detail"]},
                   "external_ping": ext["status"] if ext else None,
                   "infrastructure": {k: v for k, v in plat.items() if k != "error"},
                   "troubleshooting": {"ran": ts["ran"], "problems": ts["problems"],
                                       "info": ts["info"]},
                   "aws_evidence": aws_public(aws_ev), "online_verified": online_verified,
                   "maintenance": maint, "site_peers": peers,
                   "mcp_evidence": data, "recheck_attempts": attempts,
                   "max_rechecks": MAX_RECHECKS}
        decision, root_cause, actions = ai_decide(context)

        # guardrails: code overrides unsafe AI answers
        healthy = online_verified and not ts["problems"]
        if healthy and not maint and decision in ("RECHECK", "ESCALATE"):
            decision = "CLOSE"          # facts say online: do not escalate a false positive
        if decision == "CLOSE" and not healthy:
            decision, root_cause = "ESCALATE", "Machine not healthy or not reachable; cannot close."
        if decision == "CLOSE":
            root_cause = online_root_cause(p, aws_ev)
        if decision == "CLOSE" and mode == "MONITOR" and not MONITOR_AUTOCLOSE:
            decision = "ESCALATE"
        if (decision == "RECHECK"
                and plat.get("verdict") in ("POWERED_OFF", "HOST_DOWN", "UNHEALTHY")):
            decision = "ESCALATE"       # infrastructure already proves a real problem
        if maint and decision != "HOLD":
            decision = "HOLD"

        if decision != "RECHECK":
            break
        if attempts >= MAX_RECHECKS:
            decision, root_cause = "ESCALATE", root_cause + " Still not responding after rechecks."
            break
        attempts += 1
        z.add_note(tid, f"AI decision: RECHECK ({attempts}/{MAX_RECHECKS}). {root_cause}")
        await asyncio.sleep(RECHECK_SECONDS)
        if mode == "MANAGE":
            data = await investigate(session, alert) or data

    if decision == "CLOSE":
        note = build_online_report(alert, res, mtype, plat, p, ts, maint, decision,
                                   root_cause, mode, aws_ev)
    else:
        root_cause = offline_root_cause(res, plat, peers, root_cause)
        note = build_offline_report(alert, res, plat, p, ext, ts, maint, peers, mode,
                                    root_cause, probe_name)
    print("\n" + "=" * 70)
    print("FINAL NOC REPORT")
    print("=" * 70)
    print(note)
    print("=" * 70)
    print(f"DECISION: {decision}")
    print("=" * 70)

    z.add_note(tid, note)

    if decision == "CLOSE":
        z.add_tag(tid, "auto-closed")
        z.set_state(tid, "closed")
    elif decision == "HOLD":
        z.add_tag(tid, "maintenance-hold")
        z.set_state(tid, "pending reminder", pending_hours=HOLD_HOURS)
    else:
        z.add_tag(tid, "escalated")
        z.set_state(tid, "open")
        try:
            call_rec = call_service.place_escalation_call(
                tid, number, alert["Customer"], alert["Site"],
                alert["Machine"], "server offline")
            z.add_note(tid, call_service.format_ticket_note(call_rec))
            if call_rec["attempted"]:
                z.add_tag(tid, "ai-call-attempted")
        except Exception as e:
            print(f"Call step error (ticket not affected): {e}")
    print(f"DECISION: {decision} (ticket #{number} updated)")


async def main():
    print("\n========================================")
    print(" MSP AI AUTOMATION ENGINE v1.5")
    print("========================================")
    if PROBE_INSTANCE_ID:
        print(f"Ping probe: {PROBE_INSTANCE_ID} ({PROBE_OS}, {PROBE_REGION})")
    else:
        print("WARNING: PROBE_INSTANCE_ID is not set - every ticket will end as automation-error.")
    params = StdioServerParameters(command="python", args=[MCP_SERVER])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            print("MCP connected. Watching Zammad for new offline alerts...\n")
            while True:
                try:
                    for t in z.find_new_alerts():
                        try:
                            await process_ticket(session, t)
                        except Exception as e:
                            print(f"Automation error on ticket {t.get('number')}: {e}")
                            try:
                                z.add_note(t["id"], f"Automation error: {e}. Escalated for manual review.")
                                z.add_tag(t["id"], "automation-error")
                            except Exception:
                                pass
                except Exception as e:
                    print(f"Zammad poll error: {e}")
                await asyncio.sleep(POLL_SECONDS)


if __name__ == "__main__":
    asyncio.run(main())
