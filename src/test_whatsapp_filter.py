import unittest
import sys
import os

# Add src to the path
sys.path.append(os.path.dirname(__file__))

from whatsapp_filter import check_domain_matching, check_cidr_matching, check_inference_matching, seed_confirmed_servers, guess_media_type

class TestWhatsAppFilter(unittest.TestCase):
    def test_domain_matching(self):
        # 4a. Domain matching verification
        conf, sig = check_domain_matching(sni="mmg.whatsapp.net", dns_query=None)
        self.assertEqual(conf, "high")
        self.assertIn("domain_strong", sig)
        
        conf, sig = check_domain_matching(sni=None, dns_query="graph.whatsapp.com")
        self.assertEqual(conf, "high")
        self.assertIn("domain_strong", sig)
        
        conf, sig = check_domain_matching(sni="fbcdn.net", dns_query=None)
        self.assertEqual(conf, "low")
        self.assertIn("domain_weak", sig)
        
        conf, sig = check_domain_matching(sni="google.com", dns_query="example.org")
        self.assertEqual(conf, "none")
        self.assertEqual(sig, [])

    def test_cidr_matching(self):
        # 4b. CIDR matching verification
        conf, sig = check_cidr_matching("157.240.10.1")
        self.assertEqual(conf, "high")
        self.assertIn("cidr_strong", sig)
        conf, sig = check_cidr_matching("8.8.8.8")
        self.assertEqual(conf, "none")
        self.assertEqual(sig, [])

    def test_inference_matching(self):
        # 4c. Inference verification
        server_ip = "157.240.10.1"
        seed_confirmed_servers(server_ip)
        conf, sig = check_inference_matching(server_ip)
        self.assertEqual(conf, "medium")
        self.assertIn("inferred_server", sig)
        conf, sig = check_inference_matching("8.8.8.8")
        self.assertEqual(conf, "none")
        self.assertEqual(sig, [])

    def test_media_type_guessing(self):
        # 4d. Behavioral sub-classification verification
        self.assertEqual(guess_media_type(10, 1000, 1000, "UDP", True), "video_call")
        self.assertEqual(guess_media_type(10, 1000, 1000, "TCP", False), "message")
        self.assertEqual(guess_media_type(100, 1000000, 1000000, "TCP", False), "video")

if __name__ == '__main__':
    unittest.main()
