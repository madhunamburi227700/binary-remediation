from pull_image import pull_docker_image
from generate_vuln_list import grype_scan_image
from parse_vulns import parse_cyclonedx, save_json
from principle_1 import check_components_in_image

def main():
    # Step 1: Pull image
    image = pull_docker_image()
    if not image:
        return

    # Step 2: Generate vulnerability file
    vuln_file = grype_scan_image(image)
    if not vuln_file:
        return

    # Step 3: Parse vulnerabilities
    results, counters = parse_cyclonedx(vuln_file)
    save_json(results, counters, "parsed_vulnerabilities_raw.json")

    # Step 4: Principle #1 - Check component existence
    results, principle1_file = check_components_in_image(image, results)

    # You can continue to Step 5 for Principle #2, etc.

if __name__ == "__main__":
    main()
