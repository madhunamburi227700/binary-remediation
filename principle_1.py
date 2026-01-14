import docker
import json


def detect_os(container):
    """
    Detect OS type inside container to choose correct package manager
    """
    exit_code, output = container.exec_run("cat /etc/os-release")
    text = output.decode(errors="ignore").lower()

    if "alpine" in text:
        return "apk"
    if "debian" in text or "ubuntu" in text:
        return "deb"
    if "rhel" in text or "centos" in text:
        return "rpm"

    return "unknown"


def package_exists(container, pkg, os_type):
    """
    Check if a package exists inside the container
    """
    if not pkg or os_type == "unknown":
        return False

    if os_type == "deb":
        cmd = f"dpkg -s {pkg}"
    elif os_type == "apk":
        cmd = f"apk info {pkg}"
    elif os_type == "rpm":
        cmd = f"rpm -q {pkg}"
    else:
        return False

    exit_code, _ = container.exec_run(cmd)
    return exit_code == 0


def check_components_in_image(image,vulnerabilities,output_file="principle_1.json"):
    """
    Principle #1:
    Check whether the vulnerable component actually exists in the image.
    """
    client = docker.from_env()

    print(f"\n🔍 Starting container for image: {image}")
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
            exists = package_exists(container, pkg, os_type)
            v["1_component_exists"] = exists

            print(f"[{i}/{len(vulnerabilities)}] {pkg} -> {exists}")

    finally:
        container.remove(force=True)
        print(f"✅ Container removed: {image}")

    # ---- Summary calculation ----
    true_count = sum(1 for v in vulnerabilities if v["1_component_exists"])
    false_count = sum(1 for v in vulnerabilities if not v["1_component_exists"])

    output = {
        "summary": {
            "total_vulnerabilities": len(vulnerabilities),
            "principle_1": {
                "1_component_exists_true": true_count,
                "1_component_exists_false": false_count
            }
        },
        "vulnerabilities": vulnerabilities
    }

    with open(output_file, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\n📁 Principle #1 output saved -> {output_file}")
    print(f"✅ Component exists (TRUE) : {true_count}")
    print(f"❌ Component missing (FALSE): {false_count}")

    return vulnerabilities, output_file
