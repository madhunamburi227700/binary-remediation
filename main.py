from pull_image import pull_docker_image
from generate_vuln_list import grype_scan_image
from parse_vulns import parse_cyclonedx, save_json

def main():
    # Step 1: Pull image
    image = pull_docker_image()
    if not image:
        print("❌ Image pull failed")
        return

    # Step 2: Generate CycloneDX vulnerability file
    vuln_file = grype_scan_image(image)
    if not vuln_file:
        print("❌ Vulnerability generation failed")
        return

    # Step 3: Parse CycloneDX file
    results, counters = parse_cyclonedx(vuln_file)

    # Step 4: Save parsed output with summary
    output_file = save_json(results, counters)

    # Step 5: Print summary
    print("\n📊 Vulnerability Summary")
    print("-----------------------")
    print(f"Total vulnerabilities   : {counters['TOTAL']}")
    print(f"CVE count               : {counters['CVE']}")
    print(f"TEMP count              : {counters['TEMP']}")
    print(f"OS vulnerabilities      : {counters['OS']}")
    print(f"Library vulnerabilities : {counters['LIBRARY']}")

    print(f"\n📁 Final parsed output: {output_file}")

if __name__ == "__main__":
    main()
