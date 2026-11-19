#!/usr/bin/env python3
"""Exercise the deployed Trustee frontend and require a real TDX resource read."""

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import traceback
from urllib.parse import urlsplit

from playwright.sync_api import expect, sync_playwright


class AcceptanceError(Exception):
    """Failure message containing no response bodies or credentials."""


def check(condition, message):
    if not condition:
        raise AcceptanceError(message)


def button(container, name):
    # Ant Design inserts a space inside some two-character Chinese button labels.
    pattern = re.compile(r"\s*".join(map(re.escape, name)) + "$")
    return container.get_by_role("button", name=pattern)


def click_api(page, control, method, path):
    with page.expect_response(lambda r: (
        r.request.method == method and urlsplit(r.url).path == "/api/" + path
    )) as response:
        control.click()
    check(response.value.ok, f"{method} {path} returned {response.value.status}")
    return response.value


def visit(page, menu):
    page.get_by_role("link", name=menu, exact=True).click()


def delete_row(page, row, confirmation, path):
    button(row, "删除").click()
    click_api(page, button(page.locator(".ant-popover:visible"), confirmation), "DELETE", path)
    expect(row).to_have_count(0)


def exercise_policies(page, name):
    visit(page, "策略管理")
    button(page, "添加策略").click()
    modal = page.get_by_role("dialog")
    modal.get_by_label("策略ID").fill(name)
    modal.get_by_label("类型").fill("rego")
    policy = "package policy\ndefault allow = false\n"
    modal.get_by_label("策略内容").fill(policy)
    path = "kbs/v0/attestation-policy"
    click_api(page, button(modal, "保存"), "POST", path)
    row = page.get_by_role("row").filter(has_text=name)
    button(row, "编辑").click()
    editor = modal.get_by_label("策略内容")
    expect(editor).to_have_value(policy)
    policy += "# updated\n"
    editor.fill(policy)
    click_api(page, button(modal, "保存"), "POST", path)
    expect(modal).to_have_count(0)
    # Reopen after an independent load to verify the persisted policy.
    page.reload()
    button(row, "编辑").click()
    expect(editor).to_have_value(policy)
    button(modal, "取消").click()
    delete_row(page, row, "确认", f"{path}/{name}")
    page.get_by_role("tab", name="Resource Policy").click()
    button(page, "编辑策略").click()
    original = modal.get_by_role("textbox").input_value()
    check(original.strip(), "existing resource policy is empty")
    # Round-trip the current policy on this dedicated acceptance instance.
    click_api(page, button(modal, "保存"), "POST", "kbs/v0/resource-policy")
    page.reload()
    page.get_by_role("tab", name="Resource Policy").click()
    expect(page.locator(".policies-page pre")).to_have_text(original)


def exercise_references(page, name):
    visit(page, "参考值服务")
    page.get_by_role("tab", name="注册参考值").click()
    reference = hashlib.sha256(name.encode()).hexdigest()
    page.get_by_placeholder(re.compile("test-binary-1")).fill(json.dumps({name: [reference]}))
    click_api(page, button(page, "注册参考值"), "POST", "rvps/register")
    page.get_by_role("tab", name="查询参考值").click()
    click_api(page, button(page, "刷新参考值"), "GET", "rvps/query")
    row = page.get_by_role("row").filter(has_text=name)
    expect(row).to_contain_text(reference)
    delete_row(page, row, "确定", f"rvps/delete/{name}")


def put_resource(page, name, payload, upload_file):
    button(page, "添加资源").click()
    modal = page.get_by_role("dialog")
    # The search form and modal share field IDs in the released frontend.
    for field, value in (("repository", "shelter-e2e"), ("type", "secret"), ("tag", name)):
        modal.locator(f'input[id="{field}"]').fill(value)
    if upload_file:
        modal.get_by_text("二进制文件", exact=True).click()
        modal.locator('input[type="file"]').set_input_files({
            "name": "fixture.bin", "mimeType": "application/octet-stream", "buffer": payload,
        })
    else:
        modal.get_by_label("资源内容").fill(payload.decode())
    click_api(page, button(modal, "保存"), "POST", f"kbs/v0/resource/shelter-e2e/secret/{name}")
    expect(modal).to_have_count(0)


def resource_filter(page, name):
    visit(page, "资源管理")
    page.get_by_placeholder("输入仓库名称").fill("shelter-e2e")
    page.get_by_placeholder("输入资源类型").fill("secret")
    click_api(page, button(page, "查询"), "GET", "kbs/v0/resources")
    return page.get_by_role("row").filter(has_text=name)


def fetch_secret(command, name, payload=None):
    result = subprocess.run([command, f"shelter-e2e/secret/{name}"],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=180, check=False)
    if payload is None:
        check(result.returncode != 0, "deny-by-default policy unexpectedly released the resource")
    else:
        check(result.returncode == 0, "native TDX client failed")
        check(result.stdout.strip() == hashlib.sha256(payload).hexdigest().encode(),
              "decrypted test resource differs")


def resource_audit(page):
    visit(page, "审计日志")
    page.get_by_role("tab", name=re.compile("Resource 审计")).click()
    return page.get_by_role("tabpanel").filter(visible=True)


def check_upload_audit(page, name):
    panel = resource_audit(page)
    panel.get_by_placeholder("输入资源标签").fill(name)
    click_api(page, button(panel, "查询"), "GET", "audit/resources")
    uploads = panel.get_by_role("row").filter(has_text=name).filter(has_text="POST")
    expect(uploads.first).to_contain_text("成功")
    button(panel, "重置").click()
    expect(panel.get_by_placeholder("输入资源标签")).to_have_value("")


def audit_session(page, name, status):
    panel = resource_audit(page)
    # Gateway commits the audit record asynchronously after forwarding the request.
    page.wait_for_function("""async ([tag, status]) => {
        const auth = {headers: {Authorization: 'Bearer ' + localStorage.getItem('auth_token')}};
        const list = await fetch('/api/audit/resources?tag=' + tag, auth);
        if (!list.ok) return false;
        const entry = (await list.json()).data.find(r =>
            r.tag === tag && r.method === 'GET' && r.status === status && r.session_id);
        if (!entry) return false;
        const attestation = await fetch('/api/audit/attestation?session_id='
            + encodeURIComponent(entry.session_id), auth);
        return attestation.ok && (await attestation.json()).data.some(r =>
            r.session_id === entry.session_id && r.source_service === 'kbs' && r.successful);
    }""", arg=[name, status], polling=500)
    panel.get_by_placeholder("输入资源标签").fill(name)
    response = click_api(page, button(panel, "查询"), "GET", "audit/resources")
    gets = [r for r in response.json()["data"] if r["tag"] == name and
            r["method"] == "GET" and r["status"] == status and r["session_id"]]
    check(gets, f"missing session-bound HTTP {status} resource GET audit")
    session = gets[0]["session_id"]
    row = panel.get_by_role("row").filter(has_text=session).filter(has_text="GET").first
    with page.expect_response(lambda r: urlsplit(r.url).path == "/api/audit/attestation"
                              and "session_id=" in urlsplit(r.url).query) as linked:
        button(row, "查看关联Attestation").click()
    response = linked.value
    check(response.ok, "linked attestation audit request failed")
    records = [r for r in response.json()["data"] if r["session_id"] == session and
               r["source_service"] == "kbs" and r["successful"]]
    check(any(json.loads(r["claims"]).get("submods", {}).get("cpu0", {})
              .get("ear.veraison.annotated-evidence", {}).get("tdx") for r in records),
          "same-session KBS audit is missing verified TDX claims")
    panel = page.get_by_role("tabpanel").filter(visible=True)
    button(panel.get_by_role("row").filter(has_text=session).first, "详情").click()
    modal = page.get_by_role("dialog")
    expect(modal).to_be_visible()
    button(modal, "关闭").click()
    button(panel, "重置").click()


def open_resource_policy(page):
    visit(page, "策略管理")
    page.get_by_role("tab", name="Resource Policy").click()
    button(page, "编辑策略").click()
    return page.get_by_role("dialog")


def replace_resource_policy(page, expected, replacement):
    modal = open_resource_policy(page)
    editor = modal.get_by_role("textbox")
    check(editor.input_value() == expected, "KBS policy changed; inspect the dedicated test instance")
    editor.fill(replacement)
    click_api(page, button(modal, "保存"), "POST", "kbs/v0/resource-policy")
    expect(modal).to_have_count(0)
    expect(page.locator(".policies-page pre")).to_have_text(replacement)


def tdx_release(page, command, name, payload):
    baseline = (Path(__file__).resolve().parents[1] / "guest" / "policy.rego").read_text()
    original = open_resource_policy(page)
    check(original.get_by_role("textbox").input_value() == baseline,
          "full E2E requires an isolated instance with the shipped deny-by-default policy")
    button(original, "取消").click()
    fetch_secret(command, name)
    audit_session(page, name, 403)
    print("PASS verified TDX session denied by the baseline KBS policy", flush=True)
    template = Path(__file__).with_name("tdx-release.rego").read_text()
    temporary = template.replace("TEST_RESOURCE", f"shelter-e2e/secret/{name}")
    try:
        replace_resource_policy(page, baseline, temporary)
        fetch_secret(command, name, payload)
        audit_session(page, name, 200)
    finally:
        # If there was an error after the server applied the new policy, restore it.
        # A concurrent administrator's unrelated policy must never be overwritten.
        page.reload()
        current = open_resource_policy(page)
        value = current.get_by_role("textbox").input_value()
        button(current, "取消").click()
        if value != baseline:
            replace_resource_policy(page, temporary, baseline)


def instances(page, instance_id):
    visit(page, "实例列表")
    response = click_api(page, button(page, "刷新"), "GET", "aa-instance/list")
    items = response.json()["active_aa_instances"] or []
    search = instance_id or (items[0]["instance_id"] if items else "shelter-e2e-no-such-instance")
    if instance_id:
        check(any(i["instance_id"] == instance_id for i in items),
              "expected ECS instance heartbeat is absent")
    page.get_by_placeholder("搜索Instance ID").fill(search)
    button(page, "搜索").click()
    rows = page.locator("tbody tr.ant-table-row")
    if items:
        row = rows.filter(has=page.get_by_text(search, exact=True))
        expect(row).to_be_visible()
        if instance_id:
            expect(row.get_by_text("活跃", exact=True)).to_be_visible()
    else:
        expect(rows).to_have_count(0)
    click_api(page, button(page, "重置"), "GET", "aa-instance/list")


def cleanup(page, path):
    # Only called on failure for objects named with this run's random suffix.
    return page.evaluate("""async path => {
        const response = await fetch('/api/' + path, {method: 'DELETE', headers: {
          Authorization: 'Bearer ' + localStorage.getItem('auth_token')
        }, redirect: 'error'});
        return response.status;
    }""", path)


def check_units():
    units = ["trustee", "kbs", "as", "as-restful", "rvps", "trustee-gateway", "trustee-frontend"]
    for unit in units:
        check(subprocess.run(["systemctl", "is-active", "--quiet", unit]).returncode == 0,
              f"{unit}.service is inactive")
    print("PASS systemd service group and all six units", flush=True)


def exercise_browser(options):
    origin = urlsplit(options.origin)
    check(origin.scheme in {"http", "https"} and origin.hostname and not origin.username and
          not origin.password and origin.path in ("", "/") and not origin.fragment and
          not origin.query, "expected an HTTP(S) origin")
    # Chromium connects only to this host. A DNS name is supported for TLS SANs.
    try:
        check(ipaddress.ip_address(origin.hostname).is_loopback, "use a loopback address")
    except ValueError:
        check(origin.hostname in ("localhost", "trustee.internal"), "unsupported local DNS name")
    check(origin.scheme == "https", "use the guest HTTPS listener")
    info = options.admin_key.stat()
    check(stat.S_ISREG(info.st_mode) and info.st_mode & 0o077 == 0,
          "administrator key must be a private file")
    name = "e2e" + secrets.token_hex(12)
    with tempfile.TemporaryDirectory(prefix="trustee-browser-") as profile, sync_playwright() as playwright:
        # Give Chromium a private NSS trust store, including on hosts with a pre-existing profile.
        for subdir in (".pki/nssdb", ".local/share/pki/nssdb"):
            database = Path(profile, subdir)
            database.mkdir(parents=True, mode=0o700)
            db = ["certutil", "-d", "sql:" + str(database)]
            subprocess.run(db + ["-N", "--empty-password"], check=True)
            subprocess.run(db + ["-A", "-n", "Trustee TDVM", "-t", "C,,",
                                 "-i", str(options.ca_file)], check=True)
        args = ["--no-proxy-server", "--disable-background-networking",
                "--host-resolver-rules=MAP trustee.internal 127.0.0.1"]
        with playwright.chromium.launch(executable_path=options.chromium, args=args,
                                        env={**os.environ, "HOME": profile,
                                             "XDG_DATA_HOME": profile + "/.local/share"}) as browser:
            context = browser.new_context(service_workers="block")
            context.route("**/*", lambda route: route.continue_()
                          if urlsplit(route.request.url)[:2] == origin[:2] else route.abort())
            page = context.new_page()
            page.set_default_timeout(30000)
            errors = []
            page.on("pageerror", lambda _: errors.append("pageerror"))
            page.goto(options.origin.rstrip("/") + "/login")
            page.locator('input[type="file"]').set_input_files({
                "name": "admin.pem", "mimeType": "application/x-pem-file",
                "buffer": options.admin_key.read_bytes(),
            })
            click_api(page, button(page, "登录"), "GET", "services-health")
            health = click_api(page, button(page, "刷新"), "GET", "services-health").json()
            check(all(health[k]["status"] == "ok" for k in ("gateway", "as", "kbs", "rvps")),
                  "backend health failed")
            expect(page.get_by_text("正常", exact=True)).to_have_count(4)
            print("PASS frontend login and service health", flush=True)
            try:
                print("Checking AS and KBS policies", flush=True)
                exercise_policies(page, name)
                print("PASS AS policy CRUD and KBS resource policy round-trip", flush=True)
                exercise_references(page, name)
                print("PASS RVPS registration, query and deletion", flush=True)
                resource_filter(page, name)
                put_resource(page, name, b"initial", False)
                payload = secrets.token_bytes(48)
                put_resource(page, name, payload, True)
                expect(resource_filter(page, name)).to_be_visible()
                check_upload_audit(page, name)
                print("PASS text and binary resource upload, query and write audit", flush=True)
                if not options.management_only:
                    tdx_release(page, options.client, name, payload)
                    print("PASS TDX attestation, resource decryption and audit", flush=True)
                delete_row(page, resource_filter(page, name), "确认",
                           f"kbs/v0/resource/shelter-e2e/secret/{name}")
                instances(page, options.instance_id)
                print("PASS resource deletion and AA instance search and refresh", flush=True)
            except Exception:
                for path in (f"kbs/v0/resource/shelter-e2e/secret/{name}",
                             f"rvps/delete/{name}", f"kbs/v0/attestation-policy/{name}"):
                    try:
                        status = cleanup(page, path)
                        print(f"cleanup {path}: HTTP {status}", file=sys.stderr)
                    except Exception:
                        print(f"inspect test object {path}", file=sys.stderr)
                raise
            button(page, "登出").click()
            page.wait_for_url("**/login")
            check(page.evaluate("!localStorage.auth_token && !localStorage.private_key"),
                  "logout retained authentication data")
            check(not errors, "browser raised an uncaught page error")
            print("PASS logout", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", default="https://127.0.0.1:8082")
    parser.add_argument("--ca-file", type=Path,
                        default=Path("/var/lib/trustee-shelter/identity/ca.crt"))
    parser.add_argument("--admin-key", type=Path, required=True)
    parser.add_argument("--client", default=str(Path(__file__).with_name("tdx-client.sh")),
                        help="executable taking a test resource path, returning its SHA-256")
    parser.add_argument("--chromium", help="path to a compatible system Chromium executable")
    parser.add_argument("--management-only", action="store_true",
                        help="exercise management pages only (does not qualify as a TDX E2E pass)")
    parser.add_argument("--instance-id", help="expected ECS ID in the AA heartbeat page")
    try:
        options = parser.parse_args()
        if options.management_only:
            print("MANAGEMENT ONLY: systemd, TDX attestation, resource decryption and correlated "
                  "attestation audit are excluded", flush=True)
        else:
            check(options.instance_id and re.fullmatch(r"i-[A-Za-z0-9]+", options.instance_id),
                  "full E2E requires --instance-id with the ECS ID returned at launch")
            check_units()
        exercise_browser(options)
    except Exception as error:
        # Browser traces can contain tokens or typed values. Never print them.
        if isinstance(error, AcceptanceError):
            print(f"FAIL {error}", file=sys.stderr)
        else:
            where = [f for f in traceback.extract_tb(error.__traceback__) if f.filename == __file__][-1]
            print(f"FAIL {type(error).__name__} in {where.name} at line {where.lineno}", file=sys.stderr)
        sys.exit(1)
