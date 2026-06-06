from unittest.mock import patch

from rest_framework import status
from rest_framework.test import APITestCase

from .services import LookupService


class LookupServiceTests(APITestCase):
    def test_detects_ip_input(self):
        service = LookupService()
        input_type, normalized_value = service.detect_input_type("8.8.8.8")

        self.assertEqual(input_type, "ip")
        self.assertEqual(normalized_value, "8.8.8.8")

    def test_detects_url_input(self):
        service = LookupService()
        input_type, normalized_value = service.detect_input_type("https://example.com/login")

        self.assertEqual(input_type, "url")
        self.assertEqual(normalized_value, "https://example.com/login")

    def test_detects_domain_input(self):
        service = LookupService()
        input_type, normalized_value = service.detect_input_type("Example.COM")

        self.assertEqual(input_type, "domain")
        self.assertEqual(normalized_value, "example.com")

    def test_get_domain_from_url(self):
        service = LookupService()
        domain = service.get_domain_from_value("url", "https://sub.example.com/path")

        self.assertEqual(domain, "sub.example.com")

    @patch("lookup.services.LookupService.lookup")
    def test_lookup_endpoint_returns_combined_result(self, mocked_lookup):
        mocked_lookup.return_value = {
            "success": True,
            "input": "8.8.8.8",
            "normalized_input": "8.8.8.8",
            "input_type": "ip",
            "sources": {
                "virustotal": {
                    "source": "VirusTotal",
                    "ok": True,
                    "message": "Lookup completed successfully.",
                    "status_code": 200,
                    "data": {"sample": "value"},
                }
            },
        }

        response = self.client.post("/api/lookup/", {"value": "8.8.8.8"}, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["input_type"], "ip")
        self.assertIn("virustotal", response.data["sources"])

    def test_lookup_endpoint_rejects_blank_input(self):
        response = self.client.post("/api/lookup/", {"value": "   "}, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
