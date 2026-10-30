import os
import requests

def _load_env(path="/opt/msp-ai/zammad.env"):
    if os.path.exists(path):
        for line in open(path):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k, v)

_load_env()
URL = os.environ["ZAMMAD_URL"].rstrip("/")
HEADERS = {"Authorization": f"Token token={os.environ['ZAMMAD_TOKEN']}"}


def _req(method, path, **kw):
    r = requests.request(method, f"{URL}/api/v1{path}", headers=HEADERS, timeout=30, **kw)
    r.raise_for_status()
    return r.json() if r.text.strip() else {}


def find_new_alerts():
    """Tickets tagged offline-alert that are still in state 'new'."""
    res = _req("GET", "/tickets/search",
               params={"query": "tags:offline-alert AND state.name:new", "limit": 20})
    return res if isinstance(res, list) else []


def get_ticket_body(ticket_id):
    arts = _req("GET", f"/ticket_articles/by_ticket/{ticket_id}")
    return arts[0]["body"] if arts else ""


def parse_alert(body):
    """Reads the 'Key: value' lines the simulator puts in the ticket body."""
    d = {}
    for line in body.replace("<br>", "\n").splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            d[k.strip()] = v.strip()
    return {
        "Customer": d.get("Customer", ""),
        "Site": d.get("Site", ""),
        "Machine": d.get("Machine", ""),
        "NOCServiceLevel": d.get("NOCServiceLevel", ""),
        "AlertTime": d.get("AlertTime", ""),
    }


def add_tag(ticket_id, tag):
    _req("POST", "/tags/add", json={"object": "Ticket", "o_id": ticket_id, "item": tag})


def add_note(ticket_id, body, internal=True):
    _req("POST", "/ticket_articles", json={
        "ticket_id": ticket_id, "subject": "NOC automation",
        "body": body, "type": "note", "internal": internal})


def set_state(ticket_id, state, pending_hours=None):
    """state: open | closed | pending reminder"""
    payload = {"state": state}
    if pending_hours:
        from datetime import datetime, timedelta, timezone
        t = datetime.now(timezone.utc) + timedelta(hours=pending_hours)
        payload["pending_time"] = t.strftime("%Y-%m-%dT%H:%M:%SZ")
    _req("PUT", f"/tickets/{ticket_id}", json=payload)


def claim(ticket_id):
    add_tag(ticket_id, "automation-processing")
    set_state(ticket_id, "open")


if __name__ == "__main__":
    for t in find_new_alerts():
        print(t["id"], t["number"], t["title"])
        print(parse_alert(get_ticket_body(t["id"])))
