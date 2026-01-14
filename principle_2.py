import docker
import json
from principle_1 import detect_os


def get_installed_version(container, pkg, os_type):
    """
    Get installed package version from container
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


def normalize_version(version):
    """
    Remove ONLY epoch (part before ':').
    Everything after ':' must match exactly.

    Examples:
    1:4.17.4-2  -> 4.17.4-2
    4.17.4-2    -> 4.17.4-2
    """
    if not version:
        return None

    return version.split(":", 1)[1] if ":" in version else version


def check_version_matches(image, vulnerabilities, output_file="principle_2.json"):
    """
    Principle #2:
    JSON installed_version == container installed_version
    (epoch skipped, exact match otherwise)
    """
    client = docker.from_env()

    print(f"\n🔍 Starting container for Principle #2: {image}")
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

            # If component not present, version cannot match
            if not v.get("1_component_exists"):
                v["2_version_matches"] = False
                continue

            container_version = get_installed_version(container, pkg, os_type)
            json_version = v.get("installed_version")

            container_norm = normalize_version(container_version)
            json_norm = normalize_version(json_version)

            v["container_installed_version"] = container_version
            v["2_version_matches"] = container_norm == json_norm

            print(
                f"[{i}/{len(vulnerabilities)}] {pkg} "
                f"{container_version} (norm {container_norm}) "
                f"== {json_version} (norm {json_norm}) "
                f"-> {v['2_version_matches']}"
            )

    finally:
        container.remove(force=True)
        print(f"✅ Container removed: {image}")

    # ---- Summary ----
    true_count = sum(1 for v in vulnerabilities if v.get("2_version_matches"))
    false_count = sum(1 for v in vulnerabilities if not v.get("2_version_matches"))

    output = {
        "summary": {
            "total_vulnerabilities": len(vulnerabilities),
            "principle_2": {
                "version_matches_true": true_count,
                "version_matches_false": false_count
            }
        },
        "vulnerabilities": vulnerabilities
    }

    with open(output_file, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\n📁 Principle #2 output saved -> {output_file}")
    print(f"✅ Version match TRUE : {true_count}")
    print(f"❌ Version match FALSE: {false_count}")

    return vulnerabilities, output_file
