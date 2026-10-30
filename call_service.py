import json, os, uuid
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone, timedelta

BASE = "/opt/msp-ai"
CONTACTS_FILE = f"{BASE}/call_contacts.json"
HISTORY_FILE = f"{BASE}/call_history.jsonl"
CALL_MODE = os.getenv("CALL_MODE", "simulation")
COOLDOWN_MINUTES = 60


def _norm(v):
    return str(v or "").strip().lower()


def _mask(phone):
    p = str(phone or "")
    return "*" * max(len(p) - 4, 0) + p[-4:]


def _now():
    return datetime.now(timezone.utc)


def _load_history():
    rows = []
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        rows.append(json.loads(line))
                    except ValueError:
                        pass
    return rows


def _save(rec):
    with open(HISTORY_FILE, "a") as f:
        f.write(json.dumps(rec) + "\n")
    os.chmod(HISTORY_FILE, 0o600)


def _find_contact(customer):
    try:
        with open(CONTACTS_FILE) as f:
            c = json.load(f).get(_norm(customer))
    except (OSError, ValueError):
        return None
    return c if c and c.get("authorized") is True and c.get("phone") else None


def _is_duplicate(ticket_id, customer, machine):
    cutoff = _now() - timedelta(minutes=COOLDOWN_MINUTES)
    for r in _load_history():
        if not r.get("attempted"):
            continue
        if r.get("ticket_id") == ticket_id:
            return True
        if (_norm(r.get("customer")) == _norm(customer)
                and _norm(r.get("machine")) == _norm(machine)
                and datetime.fromisoformat(r["time"]) > cutoff):
            return True
    return False


def place_escalation_call(ticket_id, ticket_number, customer, site, machine,
                          reason, sim_reply="ACK"):
    rec = {
        "call_id": uuid.uuid4().hex[:12],
        "time": _now().isoformat(timespec="seconds"),
        "ticket_id": ticket_id,
        "ticket_number": ticket_number,
        "customer": customer,
        "site": site,
        "machine": machine,
        "mode": CALL_MODE,
        "attempted": False,
        "status": "",
        "contact": "",
        "phone": "",
        "response": "",
    }
    contact = _find_contact(customer)
    if not contact:
        rec["status"] = "BLOCKED_NO_AUTHORIZED_CONTACT"
    elif _is_duplicate(ticket_id, customer, machine):
        rec["status"] = "BLOCKED_DUPLICATE"
    elif CALL_MODE == "fake8x8":
        rec["contact"] = contact.get("contact_name", "")
        rec["phone"] = _mask(contact["phone"])

        endpoint = os.getenv(
            "FAKE_8X8_URL",
            "http://127.0.0.1:18080/api/v1/subaccounts/lab/callflows",
        ).strip()
        parsed = urllib.parse.urlparse(endpoint)

        script = (
            "Hello. This is an automated NOC assistant calling about an "
            f"infrastructure alert. Server {machine} at site {site} is offline. "
            f"Ticket number {ticket_number}. Reason: {reason}. "
            f"Please contact your IT service desk and quote ticket {ticket_number}. "
            "This is an automated notification. Goodbye."
        )

        # Fake mode must never send a request to a remote API.
        if parsed.scheme != "http" or parsed.hostname not in (
            "127.0.0.1", "localhost", "::1"
        ):
            rec["status"] = "BLOCKED_FAKE_ENDPOINT_NOT_LOOPBACK"
            rec["response"] = "Fake mode accepts loopback HTTP endpoints only."
        else:
            payload = {
                "clientRequestId": rec["call_id"],
                "callflow": [
                    {
                        "action": "makeCall",
                        "params": {
                            "source": "+10000000000",
                            "destination": str(contact["phone"]).strip(),
                        },
                    },
                    {
                        "action": "say",
                        "params": {
                            "text": script,
                            "voiceProfile": "en-GB-Emma",
                            "repetition": 1,
                            "speed": 1,
                        },
                    },
                    {"action": "hangup"},
                ],
                "labOnly": True,
            }

            request = urllib.request.Request(
                endpoint,
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                method="POST",
            )
            rec["endpoint"] = endpoint
            rec["script"] = script
            rec["attempted"] = True

            try:
                with urllib.request.urlopen(request, timeout=10) as response:
                    http_status = response.status
                    raw = response.read().decode("utf-8", errors="replace")
            except urllib.error.HTTPError as exc:
                http_status = exc.code
                raw = exc.read().decode("utf-8", errors="replace")
                rec["status"] = "FAKE_8X8_REJECTED"
                rec["response"] = raw[:500]
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                rec["status"] = "FAKE_8X8_UNREACHABLE"
                rec["response"] = (
                    f"Mock API unavailable ({type(exc).__name__}); "
                    "check that fake_8x8_server.py is running."
                )
            else:
                rec["http_status"] = http_status
                try:
                    body = json.loads(raw) if raw else {}
                except ValueError:
                    body = {}

                rec["session_id"] = str(
                    body.get("umid") or body.get("sessionId") or ""
                )
                rec["response"] = str(
                    body.get("statusMessage")
                    or body.get("sessionStatus")
                    or raw
                    or "No response body"
                )[:500]

                if (
                    http_status in (200, 201, 202)
                    and body.get("sessionStatus") == "CREATED"
                    and body.get("statusCode", 0) == 0
                ):
                    rec["status"] = "FAKE_8X8_ACCEPTED_NO_CALL_PLACED"
                else:
                    rec["status"] = "FAKE_8X8_REJECTED"

    elif CALL_MODE != "simulation":
        rec["status"] = "BLOCKED_REAL_CALLS_NOT_ENABLED"
    else:
        rec["attempted"] = True
        rec["contact"] = contact.get("contact_name", "")
        rec["phone"] = _mask(contact["phone"])
        rec["status"] = "SIMULATED_COMPLETED"
        rec["response"] = sim_reply
        rec["script"] = (
            f"This is an automated NOC assistant. Server {machine} at {site} "
            f"is offline. Reason: {reason}. Reply 1 if aware, 2 for engineer callback."
        )
    _save(rec)
    return rec


def format_ticket_note(rec):
    return (
        "AI NOC call record\n"
        f"Call ID : {rec['call_id']}\n"
        f"Time    : {rec['time']}\n"
        f"Mode    : {rec['mode']}\n"
        f"Status  : {rec['status']}\n"
        f"Contact : {rec['contact'] or 'n/a'} {rec['phone']}\n"
        f"Response: {rec['response'] or 'n/a'}\n"
        f"Ticket  : #{rec['ticket_number']}"
    )
