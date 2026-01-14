import docker
import json
from packaging.version import parse as parse_version
from principle_1 import detect_os


def get_installed_version(container, pkg, os_type):
    """
    Get installed package version from container.
    Returns None if package is not installed or command fails.
    """
    if not pkg or os_type == "unknown":
        return None

    if os_type == "deb":
        cmd = f"dpkg-query -W -f='${{Version}}' {pkg}"
    elif os_type == "apk":
        cmd = f"apk info -v {pkg}"
    elif os_type == "rpm":
        cmd = f"rpm -q --qf '%{{VERSION}}-%{{RELEASE}}' {pkg}"
    else:
        return None

    exit_code, output = container.exec_run(cmd)
    if exit_code != 0:
        return None

    return output.decode(errors="ignore").strip()


def check_not_fixed_or_mitigated(
    image,
    vulnerabilities,
    output_file="principle_3.json"
):
    """
    Principle #3:
    Check whether vulnerability is NOT fixed or mitigated
    """
    client = docker.from_env()

    print(f"\n🔍 Starting container for Principle #3: {image}")
    container = client.containers.run(
        image=image,
        command="tail -f /dev/null",
        detach=True
    )

    try:
        os_type = detect_os(container)
        print(f"🖥 Detected OS type: {os_type}")

        for i, v in enumerate(vulnerabilities, start=1):
            pkg = v.get("package")

            # If package does not exist → cannot be vulnerable
            if not v.get("1_component_exists"):
                v["3_not_fixed_or_mitigated"] = False
                reason = "package not present"
                print(f"[{i}/{len(vulnerabilities)}] {pkg} -> NOT FIXED = {v['3_not_fixed_or_mitigated']} ({reason})")
                continue

            installed_version = get_installed_version(container, pkg, os_type)
            fixed_version = v.get("fixed_version")

            v["container_installed_version"] = installed_version

            # Case 1: No fixed version available
            if not fixed_version:
                v["3_not_fixed_or_mitigated"] = True
                reason = "no fixed version available"

            # Case 2: Installed version unknown (None)
            elif installed_version is None:
                v["3_not_fixed_or_mitigated"] = True
                reason = "installed version unknown"

            # Case 3: Installed < Fixed → not fixed
            elif parse_version(installed_version) < parse_version(fixed_version):
                v["3_not_fixed_or_mitigated"] = True
                reason = "installed version lower than fixed"

            # Case 4: Installed >= Fixed → fixed
            else:
                v["3_not_fixed_or_mitigated"] = False
                reason = "fix applied"

            print(
                f"[{i}/{len(vulnerabilities)}] {pkg} | "
                f"installed={installed_version} | fixed={fixed_version} "
                f"-> NOT FIXED = {v['3_not_fixed_or_mitigated']} ({reason})"
            )

    finally:
        container.remove(force=True)
        print(f"✅ Container removed: {image}")

    # ---- Summary ----
    true_count = sum(1 for v in vulnerabilities if v.get("3_not_fixed_or_mitigated"))
    false_count = len(vulnerabilities) - true_count

    output = {
        "summary": {
            "total_vulnerabilities": len(vulnerabilities),
            "principle_3": {
                "not_fixed_true": true_count,
                "fixed_false": false_count
            }
        },
        "vulnerabilities": vulnerabilities
    }

    with open(output_file, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\n📁 Principle #3 output saved -> {output_file}")

    return vulnerabilities, output_file
