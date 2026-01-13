import subprocess

def grype_scan_image(full_image_name):
    """
    Generate CycloneDX vulnerability report using Grype (fast shell mode)
    """

    output_file = f"{full_image_name.replace('/', '_').replace(':', '_')}_vuln.json"

    command = (
        f"trivy image {full_image_name} "
        f"--format cyclonedx --scanners vuln "
        f"--pkg-types os "
        f"> {output_file}"
    )

    try:
        print("\n🔍 Running Grype command:")
        print(command)
        print("⏳ Please wait...\n")

        subprocess.run(
            command,
            shell=True,        # IMPORTANT
            check=True
        )

        print("\n✅ Vulnerability report generated successfully")
        print(f"📄 Output file: {output_file}")
        return output_file

    except subprocess.CalledProcessError:
        print("\n❌ Grype scan failed")
        return None
