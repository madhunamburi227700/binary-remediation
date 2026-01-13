import json
import re
from collections import Counter
from urllib.parse import unquote

OS_PKG_PREFIXES = (
    "pkg:deb/",
    "pkg:apk/",
    "pkg:rpm/",
    "pkg:alpine/",
    "pkg:ubuntu/"
)

def is_os_package(purl: str) -> bool:
    return purl.startswith(OS_PKG_PREFIXES)

def vuln_id_type(vuln_id: str) -> str:
    if vuln_id.startswith("CVE-"):
        return "CVE"
    if vuln_id.startswith("TEMP-"):
        return "TEMP"
    return "OTHER"

def extract_pkg_name_version(purl: str):
    try:
        purl = unquote(purl)
        main = purl.split("?")[0]
        name_version = main.split("/")[-1]
        name, version = name_version.split("@", 1)
        return name, version
    except Exception:
        return "UNKNOWN", None

def extract_fixed_versions_from_recommendation(recommendation: str):
    """
    Extract version numbers from recommendation text
    Example:
    'Upgrade linux-libc-dev to version 6.12.57-1'
    """
    if not recommendation:
        return None

    versions = re.findall(
        r'\b\d+(?:\.\d+)+(?:[-+~:\w]*)',
        recommendation
    )

    return ", ".join(sorted(set(versions))) if versions else None

def parse_cyclonedx(file_path: str):
    with open(file_path, "r") as f:
        data = json.load(f)

    vulns = data.get("vulnerabilities", [])
    results = []
    counters = Counter()

    for v in vulns:
        vuln_id = v.get("id", "UNKNOWN")
        id_type = vuln_id_type(vuln_id)
        description = v.get("description", "")

        for item in v.get("affects", []):
            purl = item.get("ref", "UNKNOWN")
            pkg_name, installed_version = extract_pkg_name_version(purl)

            fixed_version = None

            # 1️⃣ Check affects[].versions first
            for ver in item.get("versions", []):
                if ver.get("status") in ("fixed", "resolved"):
                    fixed_version = ver.get("version")
                    break

            # 2️⃣ Fallback to recommendation
            if not fixed_version:
                fixed_version = extract_fixed_versions_from_recommendation(
                    v.get("recommendation", "")
                )

            pkg_type = "OS" if is_os_package(purl) else "LIBRARY"

            counters["TOTAL"] += 1
            counters[id_type] += 1
            counters[pkg_type] += 1

            results.append({
                "vuln_id": vuln_id,
                "vuln_type": id_type,
                "package": pkg_name,
                "package_type": pkg_type,
                "installed_version": installed_version,
                "fixed_version": fixed_version,
                "description": description
            })

    return results, counters

def save_json(results, counters, output_file="parsed_vulnerabilities.json"):
    output = {
        "summary": {
            "total_vulnerabilities": counters["TOTAL"],
            "cve_count": counters["CVE"],
            "temp_count": counters["TEMP"],
            "os_vulnerabilities": counters["OS"],
            "library_vulnerabilities": counters["LIBRARY"]
        },
        "vulnerabilities": results
    }

    with open(output_file, "w") as f:
        json.dump(output, f, indent=2)

    return output_file
