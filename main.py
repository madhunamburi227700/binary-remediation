from pull_image import pull_docker_image
from generate_vuln_list import grype_scan_image
from parse_vulns import parse_cyclonedx, save_json
from principle_1 import check_components_in_image
from principle_2 import check_version_matches
from principle_3 import check_not_fixed_or_mitigated
from principle_4 import check_scanner_base_guess

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
    results, p1_file = check_components_in_image(image, results)        

    # Step 5: Principle #2 - Check version matches
    results, p2_file = check_version_matches(image, results)

    # Step 6: Principle #3 - Check not fixed or mitigated
    results, p3_file = check_not_fixed_or_mitigated(image, results)

    # Step 7: Principle #4 - Check scanner base image guessing
    results, p4_file = check_scanner_base_guess(image, results)

if __name__ == "__main__":
    main()
