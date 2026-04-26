#!/usr/bin/env python3
"""在 Cloud Shell 中批量同步 cdnip.txt 到 GCP 防火墙规则。"""

from __future__ import annotations

import argparse
import ipaddress
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Iterable, Sequence

MAX_RANGES_PER_RULE = 256
DEFAULT_RULE_PREFIX = "deny-cdn-egress-custom"
DEFAULT_BASE_PRIORITY = 900


def print_info(message: str) -> None:
    print(f"[信息] {message}")


def print_success(message: str) -> None:
    print(f"\033[92m[成功] {message}\033[0m")


def print_warning(message: str) -> None:
    print(f"\033[93m[警告] {message}\033[0m")


def run_command(command: Sequence[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, capture_output=True, text=True)
    if check and result.returncode != 0:
        stderr = (result.stderr or "").strip()
        stdout = (result.stdout or "").strip()
        detail = stderr or stdout or f"退出码 {result.returncode}"
        raise RuntimeError(f"命令执行失败: {' '.join(command)}\n{detail}")
    return result


def run_gcloud(args: Sequence[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return run_command(["gcloud", *args], check=check)


def run_gcloud_json(args: Sequence[str], *, check: bool = True):
    result = run_gcloud([*args, "--format=json"], check=check)
    text = (result.stdout or "").strip()
    if not text:
        return []
    return json.loads(text)


def ensure_gcloud() -> None:
    if shutil.which("gcloud") is None:
        raise SystemExit("未找到 gcloud。请在 Cloud Shell 中运行，或先安装并登录 Google Cloud CLI。")


def get_active_account() -> str | None:
    result = run_gcloud([
        "auth",
        "list",
        "--filter=status:ACTIVE",
        "--format=value(account)",
    ], check=False)
    account = (result.stdout or "").strip()
    return account or None


def get_default_project() -> str | None:
    result = run_gcloud(["config", "get-value", "project"], check=False)
    project_id = (result.stdout or "").strip()
    if result.returncode != 0 or not project_id or project_id == "(unset)":
        return None
    return project_id


def choose_from_list(items: Sequence[dict], title: str, label_builder) -> dict:
    print(f"\n--- {title} ---")
    for index, item in enumerate(items, start=1):
        print(f"[{index}] {label_builder(item)}")

    while True:
        choice = input(f"请输入数字选择 (1-{len(items)}): ").strip()
        if choice.isdigit():
            selected_index = int(choice) - 1
            if 0 <= selected_index < len(items):
                return items[selected_index]
        print("输入无效，请重试。")


def prompt_non_empty(prompt_text: str) -> str:
    while True:
        value = input(prompt_text).strip()
        if value:
            return value
        print("输入不能为空，请重试。")


def list_projects() -> list[dict]:
    try:
        projects = run_gcloud_json(["projects", "list", "--filter=lifecycleState:ACTIVE"])
    except RuntimeError as exc:
        print_warning(f"列出项目失败: {exc}")
        return []

    results = []
    for project in projects:
        project_id = project.get("projectId") or project.get("project_id")
        display_name = project.get("name") or project.get("displayName") or project_id
        if project_id:
            results.append({"project_id": project_id, "display_name": display_name})

    results.sort(key=lambda item: item["project_id"])
    return results


def select_project(explicit_project: str | None) -> str:
    if explicit_project:
        return explicit_project

    default_project = get_default_project()
    projects = list_projects()

    if default_project:
        print_info(f"当前 gcloud 默认项目: {default_project}")
        use_default = input("按回车直接使用，输入 n 重新选择项目: ").strip().lower()
        if use_default in {"", "y", "yes"}:
            return default_project

    if not projects:
        print_warning("无法自动列出项目，将改为手动输入。")
        return prompt_non_empty("请输入项目 ID: ")

    selected = choose_from_list(
        projects,
        "请选择目标项目",
        lambda item: f"{item['project_id']} ({item['display_name']})",
    )
    return selected["project_id"]


def extract_zone_name(zone_value: str | None) -> str:
    if not zone_value:
        return "-"
    return zone_value.split("/")[-1]


def extract_network_name(instance: dict) -> str:
    interfaces = instance.get("networkInterfaces") or []
    if not interfaces:
        return "default"
    network = interfaces[0].get("network")
    if not network:
        return "default"
    return network.split("/")[-1]


def extract_internal_ip(instance: dict) -> str:
    interfaces = instance.get("networkInterfaces") or []
    if not interfaces:
        return "-"
    return interfaces[0].get("networkIP") or "-"


def extract_external_ip(instance: dict) -> str:
    interfaces = instance.get("networkInterfaces") or []
    if not interfaces:
        return "-"
    access_configs = interfaces[0].get("accessConfigs") or []
    if not access_configs:
        return "-"
    return access_configs[0].get("natIP") or "-"


def list_instances(project_id: str) -> list[dict]:
    try:
        instances = run_gcloud_json(["compute", "instances", "list", "--project", project_id])
    except RuntimeError as exc:
        raise SystemExit(f"列出实例失败: {exc}") from exc

    normalized = []
    for instance in instances:
        normalized.append(
            {
                "name": instance.get("name", "-"),
                "zone": extract_zone_name(instance.get("zone")),
                "status": instance.get("status", "UNKNOWN"),
                "network": extract_network_name(instance),
                "internal_ip": extract_internal_ip(instance),
                "external_ip": extract_external_ip(instance),
            }
        )

    normalized.sort(key=lambda item: (item["name"], item["zone"]))
    return normalized


def select_instance(project_id: str, explicit_instance: str | None) -> dict:
    instances = list_instances(project_id)
    if not instances:
        raise SystemExit(f"项目 {project_id} 中没有任何实例。")

    if explicit_instance:
        matched = [instance for instance in instances if instance["name"] == explicit_instance]
        if len(matched) == 1:
            return matched[0]
        if len(matched) > 1:
            print_warning(f"实例名 {explicit_instance} 存在多条记录，请手动确认。")
            return choose_from_list(
                matched,
                f"请选择实例 {explicit_instance}",
                lambda item: (
                    f"{item['name']} | 区域: {item['zone']} | 状态: {item['status']} | 网络: {item['network']} "
                    f"| 内网IP: {item['internal_ip']} | 外网IP: {item['external_ip']}"
                ),
            )
        print_warning(f"未找到实例 {explicit_instance}，将改为手动选择。")

    return choose_from_list(
        instances,
        "请选择目标实例",
        lambda item: (
            f"{item['name']} | 区域: {item['zone']} | 状态: {item['status']} | 网络: {item['network']} "
            f"| 内网IP: {item['internal_ip']} | 外网IP: {item['external_ip']}"
        ),
    )


def strip_comment(line: str) -> str:
    for marker in ("#", "//"):
        position = line.find(marker)
        if position != -1:
            line = line[:position]
    return line.strip()


def read_cdn_ranges(file_path: Path) -> list[str]:
    if not file_path.is_file():
        raise SystemExit(f"找不到 cdnip 文件: {file_path}")

    seen = set()
    results: list[str] = []

    with file_path.open("r", encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            cleaned = strip_comment(raw_line)
            if not cleaned:
                continue

            token = cleaned.split()[0]
            try:
                network = ipaddress.ip_network(token, strict=False)
            except ValueError as exc:
                raise SystemExit(f"第 {line_number} 行不是合法 IP/CIDR: {token}\n{exc}") from exc

            normalized = str(network)
            if normalized in seen:
                continue
            seen.add(normalized)
            results.append(normalized)

    if not results:
        raise SystemExit(f"{file_path} 中没有任何有效的 IP/CIDR。")

    return results


def chunked(items: Sequence[str], size: int) -> Iterable[list[str]]:
    for index in range(0, len(items), size):
        yield list(items[index:index + size])


def build_rule_name(prefix: str, chunk_index: int) -> str:
    return f"{prefix}-{chunk_index:03d}"


def list_managed_rules(project_id: str, rule_prefix: str, network_name: str) -> list[dict]:
    rules = run_gcloud_json(["compute", "firewall-rules", "list", "--project", project_id])
    managed = []

    for rule in rules:
        name = rule.get("name", "")
        network = rule.get("network", "")
        network_short = network.split("/")[-1] if network else ""
        if not name.startswith(rule_prefix):
            continue
        if network_short != network_name:
            continue
        managed.append(rule)

    managed.sort(key=lambda item: item.get("name", ""))
    return managed


def delete_rule(project_id: str, rule_name: str) -> None:
    print_info(f"删除旧规则: {rule_name}")
    run_gcloud([
        "compute",
        "firewall-rules",
        "delete",
        rule_name,
        "--project",
        project_id,
        "--quiet",
    ])


def create_rule(
    project_id: str,
    rule_name: str,
    network_name: str,
    priority: int,
    destination_ranges: Sequence[str],
) -> None:
    joined_ranges = ",".join(destination_ranges)
    print_info(f"创建规则: {rule_name} | 优先级: {priority} | IP 段数: {len(destination_ranges)}")
    run_gcloud([
        "compute",
        "firewall-rules",
        "create",
        rule_name,
        "--project",
        project_id,
        "--network",
        network_name,
        "--direction=EGRESS",
        "--action=DENY",
        "--rules=all",
        f"--priority={priority}",
        f"--destination-ranges={joined_ranges}",
        "--quiet",
    ])


def confirm(prompt_text: str, *, default_yes: bool = False) -> bool:
    suffix = "[Y/n]" if default_yes else "[y/N]"
    answer = input(f"{prompt_text} {suffix}: ").strip().lower()
    if not answer:
        return default_yes
    return answer in {"y", "yes"}


def sync_firewall_rules(
    project_id: str,
    network_name: str,
    ranges: Sequence[str],
    rule_prefix: str,
    base_priority: int,
    chunk_size: int,
) -> None:
    if chunk_size > MAX_RANGES_PER_RULE:
        raise SystemExit(f"chunk-size 不能超过 {MAX_RANGES_PER_RULE}。")

    chunks = list(chunked(ranges, chunk_size))
    desired_rule_names = {build_rule_name(rule_prefix, index) for index in range(1, len(chunks) + 1)}
    existing_rules = list_managed_rules(project_id, rule_prefix, network_name)
    existing_rule_names = {rule.get('name', '') for rule in existing_rules}

    stale_rules = [rule for rule in existing_rules if rule.get("name") not in desired_rule_names]
    if stale_rules:
        print_warning("发现旧的托管规则，将在同步前删除：")
        for rule in stale_rules:
            print(f"  - {rule.get('name')}")
        if confirm("是否删除这些旧规则？"):
            for rule in stale_rules:
                delete_rule(project_id, rule["name"])
        else:
            print_warning("已跳过删除旧规则。可能会留下过期的 IP 段。")

    for index, chunk in enumerate(chunks, start=1):
        rule_name = build_rule_name(rule_prefix, index)
        if rule_name in existing_rule_names:
            delete_rule(project_id, rule_name)
        create_rule(
            project_id=project_id,
            rule_name=rule_name,
            network_name=network_name,
            priority=base_priority + index - 1,
            destination_ranges=chunk,
        )

    print_success(f"同步完成，共写入 {len(chunks)} 条规则，覆盖 {len(ranges)} 个 IP 段。")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="将 cdnip.txt 批量同步到 GCP EGRESS DENY 防火墙规则。")
    parser.add_argument("--input", default="cdnip.txt", help="本地 cdnip.txt 路径，默认当前目录下的 cdnip.txt")
    parser.add_argument("--project", help="直接指定项目 ID，省略时交互选择")
    parser.add_argument("--instance", help="直接指定实例名，省略时交互选择")
    parser.add_argument("--rule-prefix", default=DEFAULT_RULE_PREFIX, help="规则名前缀")
    parser.add_argument("--chunk-size", type=int, default=MAX_RANGES_PER_RULE, help="每条规则的 IP 段数量")
    parser.add_argument("--base-priority", type=int, default=DEFAULT_BASE_PRIORITY, help="规则起始优先级")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    ensure_gcloud()

    account = get_active_account()
    if account:
        print_info(f"当前登录账号: {account}")
    else:
        print_warning("未检测到活动账号。请先执行 gcloud auth login。")

    input_path = Path(args.input).expanduser().resolve()
    ranges = read_cdn_ranges(input_path)
    print_info(f"已从 {input_path} 读取 {len(ranges)} 个唯一 IP 段。")

    project_id = select_project(args.project)
    print_info(f"目标项目: {project_id}")

    instance = select_instance(project_id, args.instance)
    network_name = instance["network"]
    print_info(
        f"目标实例: {instance['name']} ({instance['zone']})，所属网络: {network_name}"
    )
    print_warning("防火墙规则是网络级别的，会作用于这个 VPC 网络中的实例，不只是一台机器。")
    if not confirm("确认继续同步防火墙规则？"):
        print_info("用户取消操作。")
        return

    sync_firewall_rules(
        project_id=project_id,
        network_name=network_name,
        ranges=ranges,
        rule_prefix=args.rule_prefix,
        base_priority=args.base_priority,
        chunk_size=args.chunk_size,
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n已取消。")
        sys.exit(130)
    except Exception as exc:  # pragma: no cover - 脚本模式下直接输出即可
        print(f"[失败] {exc}")
        sys.exit(1)
