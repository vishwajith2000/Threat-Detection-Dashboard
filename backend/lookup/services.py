import base64
import ipaddress
import os
from urllib.parse import urlparse

import requests


class LookupService:
    def __init__(self):
        self.timeout = 15

    def lookup(self, raw_value):
        input_type, normalized_value = self.detect_input_type(raw_value)

        result = {
            "success": True,
            "input": raw_value,
            "normalized_input": normalized_value,
            "input_type": input_type,
            "sources": {},
        }

        # Each API call is separate so one failure does not stop the rest of the lookup.
        result["sources"]["virustotal"] = self.lookup_virustotal(input_type, normalized_value)
        result["sources"]["abuseipdb"] = self.lookup_abuseipdb(input_type, normalized_value)
        result["sources"]["urlhaus"] = self.lookup_urlhaus(input_type, normalized_value)
        result["sources"]["threatfox"] = self.lookup_threatfox(input_type, normalized_value)
        result["sources"]["shodan_internetdb"] = self.lookup_shodan_internetdb(input_type, normalized_value)
        result["sources"]["greynoise_community"] = self.lookup_greynoise_community(input_type, normalized_value)
        result["sources"]["ip_api"] = self.lookup_ip_api(input_type, normalized_value)
        result["sources"]["ipapi_is"] = self.lookup_ipapi_is(input_type, normalized_value)
        result["sources"]["crt_sh"] = self.lookup_crt_sh(input_type, normalized_value)
        result["sources"]["dns_google"] = self.lookup_google_dns(input_type, normalized_value)
        result["sources"]["rdap"] = self.lookup_rdap(input_type, normalized_value)

        return result

    def detect_input_type(self, raw_value):
        cleaned_value = raw_value.strip()

        if self.is_url(cleaned_value):
            return "url", cleaned_value

        if self.is_ip_address(cleaned_value):
            return "ip", cleaned_value

        # If it is not a URL or IP, we treat it like a domain-style input.
        return "domain", cleaned_value.lower()

    def is_url(self, value):
        parsed = urlparse(value)
        return parsed.scheme in {"http", "https"} and bool(parsed.netloc)

    def is_ip_address(self, value):
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def get_domain_from_value(self, input_type, value):
        if input_type == "url":
            parsed = urlparse(value)
            return (parsed.hostname or "").lower()

        if input_type == "domain":
            return value.lower()

        return None

    def build_result(self, source_name, ok, message, data=None, status_code=None):
        return {
            "source": source_name,
            "ok": ok,
            "message": message,
            "status_code": status_code,
            "data": data,
        }

    def missing_key_result(self, source_name, env_name):
        return self.build_result(
            source_name,
            False,
            f"Skipped because {env_name} is missing in backend/.env.",
        )

    def unsupported_result(self, source_name, reason):
        return self.build_result(source_name, False, reason)

    def request_json(self, method, url, source_name, headers=None, params=None, json_body=None):
        try:
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                json=json_body,
                timeout=self.timeout,
            )

            payload = None
            if response.text:
                try:
                    payload = response.json()
                except ValueError:
                    payload = {"raw_text": response.text}

            if response.ok:
                return self.build_result(
                    source_name,
                    True,
                    "Lookup completed successfully.",
                    payload,
                    response.status_code,
                )

            return self.build_result(
                source_name,
                False,
                f"API returned HTTP {response.status_code}.",
                payload,
                response.status_code,
            )
        except requests.RequestException as error:
            return self.build_result(source_name, False, f"Request failed: {error}")

    def lookup_virustotal(self, input_type, value):
        api_key = os.getenv("VIRUSTOTAL_API_KEY")
        if not api_key:
            return self.missing_key_result("VirusTotal", "VIRUSTOTAL_API_KEY")

        if input_type == "ip":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{value}"
        elif input_type == "domain":
            url = f"https://www.virustotal.com/api/v3/domains/{value}"
        elif input_type == "url":
            url_id = self.url_to_virustotal_id(value)
            url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        else:
            return self.unsupported_result("VirusTotal", "This input type is not supported by VirusTotal in this app.")

        headers = {"x-apikey": api_key}
        return self.request_json("GET", url, "VirusTotal", headers=headers)

    def url_to_virustotal_id(self, url):
        # VirusTotal expects a URL-safe base64 identifier for URL lookups.
        encoded = base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8")
        return encoded.rstrip("=")

    def lookup_abuseipdb(self, input_type, value):
        if input_type != "ip":
            return self.unsupported_result("AbuseIPDB", "AbuseIPDB is only used for IP lookups.")

        api_key = os.getenv("ABUSEIPDB_API_KEY")
        if not api_key:
            return self.missing_key_result("AbuseIPDB", "ABUSEIPDB_API_KEY")

        headers = {"Key": api_key, "Accept": "application/json"}
        params = {"ipAddress": value, "maxAgeInDays": 90, "verbose": True}

        return self.request_json(
            "GET",
            "https://api.abuseipdb.com/api/v2/check",
            "AbuseIPDB",
            headers=headers,
            params=params,
        )

    def lookup_urlhaus(self, input_type, value):
        if input_type != "url":
            return self.unsupported_result("URLHaus", "URLHaus is only used for URL lookups.")

        abuse_ch_auth_key = os.getenv("ABUSE_CH_AUTH_KEY") or os.getenv("THREATFOX_AUTH_KEY")
        headers = {}
        if abuse_ch_auth_key:
            headers["Auth-Key"] = abuse_ch_auth_key

        try:
            response = requests.post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                headers=headers,
                data={"url": value},
                timeout=self.timeout,
            )

            try:
                payload = response.json()
            except ValueError:
                payload = {"raw_text": response.text}

            if response.ok:
                return self.build_result("URLHaus", True, "Lookup completed successfully.", payload, response.status_code)

            return self.build_result(
                "URLHaus",
                False,
                f"API returned HTTP {response.status_code}.",
                payload,
                response.status_code,
            )
        except requests.RequestException as error:
            return self.build_result("URLHaus", False, f"Request failed: {error}")

    def lookup_threatfox(self, input_type, value):
        auth_key = os.getenv("THREATFOX_AUTH_KEY")
        if not auth_key:
            return self.missing_key_result("ThreatFox", "THREATFOX_AUTH_KEY")

        search_term = value
        if input_type == "domain":
            search_term = value
        elif input_type == "url":
            search_term = value
        elif input_type == "ip":
            search_term = value
        else:
            return self.unsupported_result("ThreatFox", "ThreatFox is only used for IP, domain, or URL lookups.")

        headers = {
            "Auth-Key": auth_key,
            "Content-Type": "application/json",
        }
        payload = {
            "query": "search_ioc",
            "search_term": search_term,
            "exact_match": True,
        }

        return self.request_json(
            "POST",
            "https://threatfox-api.abuse.ch/api/v1/",
            "ThreatFox",
            headers=headers,
            json_body=payload,
        )

    def lookup_shodan_internetdb(self, input_type, value):
        if input_type != "ip":
            return self.unsupported_result("Shodan InternetDB", "Shodan InternetDB is only used for IP lookups.")

        return self.request_json(
            "GET",
            f"https://internetdb.shodan.io/{value}",
            "Shodan InternetDB",
        )

    def lookup_greynoise_community(self, input_type, value):
        if input_type != "ip":
            return self.unsupported_result("GreyNoise Community", "GreyNoise Community is only used for IP lookups.")

        headers = {"Accept": "application/json"}

        # GreyNoise allows limited unauthenticated community lookups, but we also support
        # an optional API key for users who have a free account.
        greynoise_api_key = os.getenv("GREYNOISE_API_KEY")
        if greynoise_api_key:
            headers["key"] = greynoise_api_key

        return self.request_json(
            "GET",
            f"https://api.greynoise.io/v3/community/{value}",
            "GreyNoise Community",
            headers=headers,
        )

    def lookup_ip_api(self, input_type, value):
        if input_type != "ip":
            return self.unsupported_result("IP-API", "IP-API is only used for IP lookups.")

        params = {
            "fields": "status,message,country,countryCode,regionName,city,isp,org,as,mobile,proxy,hosting,query"
        }

        api_result = self.request_json(
            "GET",
            f"http://ip-api.com/json/{value}",
            "IP-API",
            params=params,
        )

        if api_result["ok"] and api_result["data"] and api_result["data"].get("status") == "fail":
            return self.build_result(
                "IP-API",
                False,
                api_result["data"].get("message", "IP-API did not return a successful lookup."),
                api_result["data"],
                api_result["status_code"],
            )

        return api_result

    def lookup_ipapi_is(self, input_type, value):
        if input_type != "ip":
            return self.unsupported_result("ipapi.is", "ipapi.is is only used for IP lookups.")

        return self.request_json(
            "GET",
            "https://api.ipapi.is/",
            "ipapi.is",
            params={"q": value},
        )

    def lookup_crt_sh(self, input_type, value):
        domain = self.get_domain_from_value(input_type, value)
        if not domain:
            return self.unsupported_result("crt.sh", "crt.sh is only used for domain or URL host lookups.")

        return self.request_json(
            "GET",
            "https://crt.sh/",
            "crt.sh",
            params={"q": domain, "output": "json"},
        )

    def lookup_google_dns(self, input_type, value):
        domain = self.get_domain_from_value(input_type, value)
        if not domain:
            return self.unsupported_result("Google DNS", "DNS lookup is only used for domain or URL host lookups.")

        dns_types = ["A", "AAAA", "MX", "TXT"]
        records = {}
        overall_ok = True

        for record_type in dns_types:
            api_result = self.request_json(
                "GET",
                "https://dns.google/resolve",
                f"Google DNS {record_type}",
                params={"name": domain, "type": record_type},
            )
            records[record_type] = api_result

            if not api_result["ok"]:
                overall_ok = False

        if overall_ok:
            message = "DNS lookups completed successfully."
        else:
            message = "Some DNS record lookups had issues."

        return self.build_result("Google DNS", overall_ok, message, records)

    def lookup_rdap(self, input_type, value):
        if input_type == "ip":
            object_type = "ip"
            object_value = value
        else:
            domain = self.get_domain_from_value(input_type, value)
            if not domain:
                return self.unsupported_result("RDAP", "RDAP is only used for IPs, domains, or URL host lookups.")

            object_type = "domain"
            object_value = domain

        # RDAP is the modern replacement for WHOIS and works well for both domains and IPs.
        return self.request_json(
            "GET",
            f"https://rdap.org/{object_type}/{object_value}",
            "RDAP",
            headers={"Accept": "application/rdap+json, application/json"},
        )
