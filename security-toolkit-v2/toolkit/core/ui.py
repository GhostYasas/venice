"""
ui.py
All terminal presentation lives here: colors, the banner, section
dividers, and the risk-score bar. Uses colorama so colors work correctly
on Windows cmd.exe as well as Mac/Linux terminals.
"""

from colorama import init, Fore, Back, Style

init(autoreset=True)

SEVERITY_COLOR = {
    "high": Fore.LIGHTRED_EX,
    "medium": Fore.LIGHTYELLOW_EX,
    "low": Fore.LIGHTCYAN_EX,
}

SEVERITY_ICON = {
    "high": "✖",
    "medium": "▲",
    "low": "●",
}

BANNER = f"""{Fore.LIGHTGREEN_EX}
  ███████╗███████╗ ██████╗███████╗ ██████╗
  ██╔════╝██╔════╝██╔════╝╚══███╔╝██╔═══██╗
  ███████╗█████╗  ██║       ███╔╝ ██║   ██║
  ╚════██║██╔══╝  ██║      ███╔╝  ██║   ██║
  ███████║███████╗╚██████╗███████╗╚██████╔╝
  ╚══════╝╚══════╝ ╚═════╝╚══════╝ ╚═════╝
{Style.RESET_ALL}{Fore.WHITE}      Security Toolkit — email & url checks{Style.RESET_ALL}
"""


def print_banner():
    print(BANNER)


def divider(char="─", width=62, color=Fore.LIGHTBLACK_EX):
    print(f"{color}{char * width}{Style.RESET_ALL}")


def section_title(title: str):
    print(f"{Fore.LIGHTGREEN_EX}{Style.BRIGHT}  {title}{Style.RESET_ALL}")
    divider()


def kv(label: str, value: str, label_width: int = 16):
    print(f"{Fore.LIGHTBLACK_EX}{label:<{label_width}}{Style.RESET_ALL}{value}")


def risk_bar(score: int, width: int = 30) -> str:
    """Builds a colored ASCII bar representing a 0-100 risk score."""
    filled = int((score / 100) * width)
    empty = width - filled

    if score >= 60:
        color = Fore.LIGHTRED_EX
    elif score >= 30:
        color = Fore.LIGHTYELLOW_EX
    elif score > 0:
        color = Fore.LIGHTCYAN_EX
    else:
        color = Fore.LIGHTGREEN_EX

    bar = f"{color}{'█' * filled}{Fore.LIGHTBLACK_EX}{'░' * empty}{Style.RESET_ALL}"
    return f"[{bar}] {color}{score}/100{Style.RESET_ALL}"


def print_risk_result(score: int, label: str):
    divider()
    print(f"  {Style.BRIGHT}RISK SCORE{Style.RESET_ALL}  {risk_bar(score)}")
    print(f"  {Style.BRIGHT}{label}{Style.RESET_ALL}")
    divider()


def print_findings(findings: list):
    if not findings:
        print(f"  {Fore.LIGHTGREEN_EX}✔ No issues found.{Style.RESET_ALL}")
        return

    # Sort so high severity shows first
    order = {"high": 0, "medium": 1, "low": 2}
    findings = sorted(findings, key=lambda f: order.get(f.get("severity", "low"), 3))

    for f in findings:
        sev = f.get("severity", "low")
        color = SEVERITY_COLOR.get(sev, "")
        icon = SEVERITY_ICON.get(sev, "•")
        print(f"  {color}{icon} [{sev.upper()}]{Style.RESET_ALL} {f['message']}")


def print_note(text: str):
    print(f"  {Fore.LIGHTBLACK_EX}ℹ {text}{Style.RESET_ALL}")


def print_error(text: str):
    print(f"  {Fore.LIGHTRED_EX}✖ {text}{Style.RESET_ALL}")


def menu_option(number: str, text: str):
    print(f"  {Fore.LIGHTGREEN_EX}{Style.BRIGHT}{number}{Style.RESET_ALL}  {text}")
