import json
import time
import sys
from datetime import datetime, timezone

import requests
import yaml


# --- OpenAPI Spec Parser ---

def parse_openapi_spec(spec_path):
    """Parse an OpenAPI YAML spec and extract fuzz targets."""
    with open(spec_path, "r") as f:
        spec = yaml.safe_load(f)

    base_url = spec["servers"][0]["url"]
    fuzz_targets = []

    for path, methods in spec.get("paths", {}).items():
        for method, details in methods.items():
            if method not in ("get", "post", "put", "delete", "patch"):
                continue
            target = {
                "path": path,
                "method": method.upper(),
                "base_url": base_url,
                "path_params": [],
                "body_schema": None,
                "expected_statuses": [],
                "requires_auth": False,
            }
            for param in details.get("parameters", []):
                if param.get("in") == "path":
                    target["path_params"].append({
                        "name": param["name"],
                        "type": param.get("schema", {}).get("type", "string"),
                    })
            request_body = details.get("requestBody", {})
            content = request_body.get("content", {})
            json_content = content.get("application/json", {})
            if json_content:
                target["body_schema"] = json_content.get("schema", {})
            for status_code in details.get("responses", {}).keys():
                target["expected_statuses"].append(str(status_code))
            if details.get("security"):
                target["requires_auth"] = True

            fuzz_targets.append(target)

    return fuzz_targets


# --- Mutation Strategies ---

class MutationEngine:
    """Generates mutated payloads for fuzzing."""

    BOUNDARY_STRINGS = [
        "",
        " ",
        "a" * 10000,
        "null",
        "undefined",
        "0",
        "-1",
        "99999999999999999999",
        "\x00",
        "\n\r\n",
    ]

    BOUNDARY_INTEGERS = [
        0, -1, -999999999, 999999999, 2147483647, -2147483648,
    ]

    TYPE_CONFUSION = [
        None,
        True,
        False,
        [],
        {},
        [None],
        {"__proto__": "polluted"},
        12345,
        3.14159,
    ]

    INJECTION_PAYLOADS = [
        "' OR 1=1--",
        "'; DROP TABLE users;--",
        "1; SELECT * FROM users",
        "UNION SELECT NULL,NULL,NULL--",
        "; ls -la",
        "| cat /etc/passwd",
        "$(whoami)",
        "`id`",
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "{{7*7}}",
        "${7*7}",
    ]

    AUTH_BYPASS_HEADERS = [
        {},
        {"Authorization": ""},
        {"Authorization": "Bearer "},
        {"Authorization": "Bearer AAAAAAAAAA"},
        {"Authorization": "Bearer null"},
        {"Authorization": "Basic YWRtaW46YWRtaW4="},
        {"Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ."},
    ]

    def mutate_path_param(self, param_type):
        mutations = []
        if param_type == "integer":
            mutations.extend([str(v) for v in self.BOUNDARY_INTEGERS])
            mutations.extend(["abc", "", "null", "1.5", "1e10", "-0", "0x1A"])
        else:
            mutations.extend(self.BOUNDARY_STRINGS)
            mutations.extend(self.INJECTION_PAYLOADS)
        return mutations

    def mutate_body(self, schema):
        mutations = []
        properties = schema.get("properties", {})
        required_fields = schema.get("required", [])

        for field_name, field_schema in properties.items():
            field_type = field_schema.get("type", "string")
            payloads = self._get_payloads_for_type(field_type)
            for payload in payloads:
                body = self._build_valid_body(properties)
                body[field_name] = payload
                mutations.append(body)

        for field_name in required_fields:
            body = self._build_valid_body(properties)
            del body[field_name]
            mutations.append(body)

        body = self._build_valid_body(properties)
        body["__admin"] = True
        body["role"] = "admin"
        body["extra_field"] = "A" * 5000
        mutations.append(body)

        mutations.append(None)
        mutations.append([])
        mutations.append("just a string")
        mutations.append(12345)

        return mutations

    def mutate_auth_headers(self):
        """Generate mutated Authorization headers for auth bypass testing."""
        return self.AUTH_BYPASS_HEADERS

    def _get_payloads_for_type(self, field_type):
        payloads = []
        if field_type == "string":
            payloads.extend(self.BOUNDARY_STRINGS)
            payloads.extend(self.INJECTION_PAYLOADS)
            payloads.extend(self.TYPE_CONFUSION)
        elif field_type == "integer" or field_type == "number":
            payloads.extend(self.BOUNDARY_INTEGERS)
            payloads.extend(self.BOUNDARY_STRINGS[:5])
            payloads.extend([None, True, [], {}])
        else:
            payloads.extend(self.BOUNDARY_STRINGS)
            payloads.extend(self.TYPE_CONFUSION)
        return payloads

    def _build_valid_body(self, properties):
        body = {}
        for field_name, field_schema in properties.items():
            field_type = field_schema.get("type", "string")
            if field_type == "string":
                body[field_name] = "fuzztest"
            elif field_type == "integer":
                body[field_name] = 1
            elif field_type == "number":
                body[field_name] = 1.0
            elif field_type == "boolean":
                body[field_name] = True
            else:
                body[field_name] = "fuzztest"
        return body


# --- Response Classifier ---

class ResponseClassifier:
    """Classifies API responses into severity categories."""

    SEVERITY_CRASH = "CRASH"
    SEVERITY_UNEXPECTED = "UNEXPECTED_STATUS"
    SEVERITY_INTERESTING = "INTERESTING"
    SEVERITY_TIMEOUT = "TIMEOUT"
    SEVERITY_AUTH_BYPASS = "AUTH_BYPASS"

    ERROR_SIGNATURES = [
        "traceback",
        "exception",
        "error",
        "stack trace",
        "internal server error",
        "syntax error",
        "database error",
    ]

    def classify(self, response, expected_statuses, payload_description):
        if response is None:
            return {
                "severity": self.SEVERITY_TIMEOUT,
                "description": "Request timed out",
                "payload": payload_description,
                "status_code": None,
                "response_snippet": None,
            }

        status = response.status_code
        body_text = response.text[:500] if response.text else ""

        if status >= 500:
            return {
                "severity": self.SEVERITY_CRASH,
                "description": f"Server returned {status}",
                "payload": payload_description,
                "status_code": status,
                "response_snippet": body_text,
            }

        if str(status) not in expected_statuses:
            body_lower = body_text.lower()
            has_error_sig = any(
                sig in body_lower for sig in self.ERROR_SIGNATURES
            )
            if has_error_sig:
                return {
                    "severity": self.SEVERITY_INTERESTING,
                    "description": f"Unexpected status {status} with error signature in body",
                    "payload": payload_description,
                    "status_code": status,
                    "response_snippet": body_text,
                }
            return {
                "severity": self.SEVERITY_UNEXPECTED,
                "description": f"Unexpected status code: {status}",
                "payload": payload_description,
                "status_code": status,
                "response_snippet": body_text,
            }

        return None

    def classify_auth_bypass(self, response, payload_description):
        """Classify a response for auth bypass detection."""
        if response is None:
            return None
        status = response.status_code
        body_text = response.text[:500] if response.text else ""
        # If a protected endpoint returns 200 with bad/missing creds, it is a bypass
        if status == 200:
            return {
                "severity": self.SEVERITY_AUTH_BYPASS,
                "description": "Protected endpoint accessible without valid authentication",
                "payload": payload_description,
                "status_code": status,
                "response_snippet": body_text,
            }
        return None


# --- Fuzzer Core ---

class APIFuzzer:
    """Main fuzzer that orchestrates parsing, mutation, and classification."""

    def __init__(self, spec_path, delay=0.05):
        self.spec_path = spec_path
        self.delay = delay
        self.mutation_engine = MutationEngine()
        self.classifier = ResponseClassifier()
        self.findings = []
        self.requests_sent = 0

    def run(self):
        """Run the fuzzer against all targets in the spec."""
        print(f"[*] Parsing OpenAPI spec: {self.spec_path}")
        targets = parse_openapi_spec(self.spec_path)
        print(f"[*] Found {len(targets)} endpoints to fuzz\n")

        for target in targets:
            self._fuzz_target(target)

        # Auth bypass testing on protected endpoints
        auth_targets = [t for t in targets if t["requires_auth"]]
        if auth_targets:
            print(f"\n[*] Running auth bypass checks on {len(auth_targets)} protected endpoints...")
            for target in auth_targets:
                self._fuzz_auth_bypass(target)

        self._print_summary()
        self._save_report()

    def _fuzz_target(self, target):
        path = target["path"]
        method = target["method"]
        base_url = target["base_url"]
        print(f"[*] Fuzzing {method} {path}...")

        for param in target["path_params"]:
            mutations = self.mutation_engine.mutate_path_param(param["type"])
            for mutation in mutations:
                url = base_url + path.replace(
                    "{" + param["name"] + "}", str(mutation)
                )
                self._send_and_classify(
                    method, url, None, target["expected_statuses"],
                    f"path_param[{param['name']}]={mutation!r}"
                )

        if target["body_schema"]:
            mutations = self.mutation_engine.mutate_body(target["body_schema"])
            url = base_url + path
            for mutation in mutations:
                self._send_and_classify(
                    method, url, mutation, target["expected_statuses"],
                    f"body={json.dumps(mutation)[:200]}"
                )

    def _fuzz_auth_bypass(self, target):
        """Test a protected endpoint with mutated auth headers."""
        path = target["path"]
        method = target["method"]
        base_url = target["base_url"]
        url = base_url + path

        auth_mutations = self.mutation_engine.mutate_auth_headers()
        for headers in auth_mutations:
            self.requests_sent += 1
            response = None
            try:
                if method == "GET":
                    response = requests.get(url, headers=headers, timeout=5)
                elif method == "POST":
                    response = requests.post(url, headers=headers, json={}, timeout=5)
            except requests.exceptions.Timeout:
                response = None
            except requests.exceptions.ConnectionError:
                continue

            header_desc = json.dumps(headers) if headers else "no auth header"
            finding = self.classifier.classify_auth_bypass(
                response, f"auth_header={header_desc}"
            )
            if finding:
                finding["endpoint"] = f"{method} {url}"
                finding["timestamp"] = datetime.now(timezone.utc).isoformat()
                self.findings.append(finding)

            time.sleep(self.delay)

    def _send_and_classify(self, method, url, body, expected_statuses, payload_desc):
        self.requests_sent += 1
        response = None
        try:
            if method == "GET":
                response = requests.get(url, timeout=5)
            elif method == "POST":
                response = requests.post(url, json=body, timeout=5)
            elif method == "PUT":
                response = requests.put(url, json=body, timeout=5)
            elif method == "DELETE":
                response = requests.delete(url, timeout=5)
        except requests.exceptions.Timeout:
            response = None
        except requests.exceptions.ConnectionError:
            return

        finding = self.classifier.classify(response, expected_statuses, payload_desc)
        if finding:
            finding["endpoint"] = f"{method} {url}"
            finding["timestamp"] = datetime.now(timezone.utc).isoformat()
            self.findings.append(finding)

        time.sleep(self.delay)

    def _print_summary(self):
        print(f"\n{'='*60}")
        print(f"FUZZING COMPLETE")
        print(f"{'='*60}")
        print(f"Requests sent: {self.requests_sent}")
        print(f"Issues found:  {len(self.findings)}")

        if self.findings:
            severity_counts = {}
            for f in self.findings:
                sev = f["severity"]
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            print(f"\nBreakdown by severity:")
            for sev, count in sorted(severity_counts.items()):
                print(f"  {sev}: {count}")

            print(f"\nTop findings:")
            for finding in self.findings[:5]:
                print(f"  [{finding['severity']}] {finding['endpoint']}")
                print(f"    Payload: {finding['payload'][:80]}")
                print()

    def _save_report(self):
        report = {
            "scan_metadata": {
                "spec_file": self.spec_path,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "requests_sent": self.requests_sent,
                "issues_found": len(self.findings),
            },
            "findings": self.findings,
        }
        with open("findings.json", "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[*] Full report saved to findings.json")


if __name__ == "__main__":
    spec_file = "openapi.yaml"
    if len(sys.argv) > 1:
        spec_file = sys.argv[1]
    fuzzer = APIFuzzer(spec_file)
    fuzzer.run()