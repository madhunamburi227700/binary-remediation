import docker

def detect_os(container):
    """
    Detect OS type inside container to choose correct package manager
    """
    exit_code, output = container.exec_run("cat /etc/os-release")
    text = output.decode().lower()

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


def check_components_in_image(image, vulnerabilities):
    """
    Add 'component_exists' field to each vulnerability
    """
    client = docker.from_env()

    print(f"\n🔍 Starting container for image: {image} ...")
    # Run container detached
    container = client.containers.run(
        image=image,
        command="sleep 300",
        detach=True
    )

    try:
        os_type = detect_os(container)
        print(f"🖥 Detected OS type: {os_type}")

        for v in vulnerabilities:
            pkg = v["package"]
            exists = package_exists(container, pkg, os_type)
            v["component_exists"] = exists

    finally:
        # Stop and remove container
        container.remove(force=True)
        print(f"✅ Container removed: {image}")

    return vulnerabilities
