from rich.console import Console

from core_engine import platform_utils

console = Console()

def remediate(flagged_list):
    actions = []

    for item in flagged_list:
        program = item["program"].lower()
        port = item["port"]
        pid = item["pid"]
        reason = item["reason"]

        if "unknown program" in reason and port.isdigit() and int(port) > 40000:
            actions.append({
                "action": "kill_process",
                "pid": pid,
                "reason": reason
            })

        elif "sensitive port" in reason:
            actions.append({
                "action": "kill_process",
                "pid": pid,
                "reason": reason
            })

        elif "excessive outbound" in reason:
            actions.append({
                "action": "log_only",
                "program": program,
                "reason": reason
            })

    return actions


def execute_actions(actions):
    for action in actions:
        if action["action"] == "kill_process":
            try:
                platform_utils.terminate_pid(int(action["pid"]), force=True)
                console.print(f"[bold red]💀 Killed suspicious PID {action['pid']}[/bold red]")
            except Exception as e:
                console.print(f"[yellow]⚠ Could not kill PID {action['pid']}: {e}[/yellow]")

        elif action["action"] == "log_only":
            console.print(f"[blue]📝 Logged excessive behavior for {action['program']}[/blue]")
