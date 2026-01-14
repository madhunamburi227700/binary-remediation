import docker
import json
from principle_1 import detect_os, package_exists


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


def strip_epoch(version):
    """
    Remove ONLY the epoch (part before ':').
    Everything after ':' must match exactly.
    """
    if not version:
        return None
    return version.split(":", 1)[1] if ":" in version else version


def check_scanner_base_guess(image, vulnerabilities, output_file="principle_4.json"):
    """
    Principle #4:
    Check whether the scanner is NOT guessing versions
    based on base image metadata.
    """
    client = docker.from_env()

    print(f"\n🔍 Starting container for Principle #4: {image}")
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

            if not v.get("1_component_exists"):
                v["4_scanner_not_guessing"] = True
                print(f"[{i}/{len(vulnerabilities)}] {pkg} -> Component missing, skipping")
                continue

            installed_version = get_installed_version(container, pkg, os_type)
            json_version = v.get("installed_version")

            installed_norm = strip_epoch(installed_version)
            json_norm = strip_epoch(json_version)

            v["container_installed_version"] = installed_version

            # ---- Core decision ----
            if not installed_norm or not json_norm:
                scanner_guessing = True
                reason = "unable to normalize versions"
            elif installed_norm != json_norm:
                scanner_guessing = True
                reason = f"normalized installed ({installed_norm}) != reported ({json_norm})"
            else:
                scanner_guessing = False
                reason = "normalized versions match"

            # ---- INVERT FLAG HERE ----
            v["4_scanner_not_guessing"] = not scanner_guessing

            print(
                f"[{i}/{len(vulnerabilities)}] {pkg} | "
                f"installed={installed_version} (norm {installed_norm}) | "
                f"reported={json_version} (norm {json_norm}) "
                f"-> Scanner NOT guessing = {v['4_scanner_not_guessing']} ({reason})"
            )

    finally:
        container.remove(force=True)
        print(f"✅ Container removed: {image}")

    # ---- Summary ----
    true_count = sum(1 for v in vulnerabilities if v.get("4_scanner_not_guessing"))
    false_count = len(vulnerabilities) - true_count

    output = {
        "summary": {
            "total_vulnerabilities": len(vulnerabilities),
            "principle_4": {
                "scanner_not_guessing_true": true_count,
                "scanner_not_guessing_false": false_count
            }
        },
        "vulnerabilities": vulnerabilities
    }

    with open(output_file, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\n📁 Principle #4 output saved -> {output_file}")
    print(f"✅ Scanner NOT guessing TRUE : {true_count}")
    print(f"❌ Scanner NOT guessing FALSE: {false_count}")

    return vulnerabilities, output_file
