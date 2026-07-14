import unittest
from unittest.mock import MagicMock, patch
import csv
import io
import os
import sys
from datetime import datetime, timedelta

# Add src to python path if needed
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from main import convert_pcap_to_csv

class TestConvertPcapToCsv(unittest.TestCase):
    @patch('pyshark.FileCapture')
    @patch('builtins.open', new_callable=unittest.mock.mock_open)
    def test_first_packet_is_written(self, mock_open, mock_file_capture):
        # Setup mock packets
        now = datetime.now()
        
        packet1 = MagicMock()
        packet1.sniff_time = now
        packet1.number = '1'
        packet1.highest_layer = 'TCP'
        packet1.length = '100'
        packet1.info = 'Packet 1 Info'
        # To simulate 'ip' in packet
        packet1.__contains__.side_effect = lambda key: key == 'ip'
        packet1.ip = MagicMock()
        packet1.ip.src = '192.168.1.1'
        packet1.ip.dst = '192.168.1.2'

        packet2 = MagicMock()
        packet2.sniff_time = now + timedelta(seconds=5)
        packet2.number = '2'
        packet2.highest_layer = 'UDP'
        packet2.length = '200'
        packet2.info = 'Packet 2 Info'
        packet2.__contains__.side_effect = lambda key: key == 'ip'
        packet2.ip = MagicMock()
        packet2.ip.src = '192.168.1.3'
        packet2.ip.dst = '192.168.1.4'

        # Set mock iterator for FileCapture
        mock_capture_instance = MagicMock()
        mock_capture_instance.__iter__.return_value = iter([packet1, packet2])
        mock_file_capture.return_value = mock_capture_instance

        # We want to catch the written CSV rows
        class MockFile:
            def __init__(self):
                self.output = io.StringIO()
            def write(self, s):
                self.output.write(s)
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def getvalue(self):
                return self.output.getvalue()

        mock_file = MockFile()
        mock_open.return_value = mock_file

        convert_pcap_to_csv('dummy.pcap', 'dummy.csv')

        # Check what was written to CSV
        csv_content = mock_file.getvalue()
        reader = csv.DictReader(io.StringIO(csv_content))
        rows = list(reader)

        # Assertions
        self.assertEqual(len(rows), 2)
        
        # Check first packet row
        self.assertEqual(rows[0]['No.'], '1')
        self.assertEqual(float(rows[0]['Time']), 0.0)
        self.assertEqual(rows[0]['Source'], '192.168.1.1')
        self.assertEqual(rows[0]['Destination'], '192.168.1.2')
        self.assertEqual(rows[0]['Protocol'], 'TCP')
        self.assertEqual(rows[0]['Length'], '100')
        self.assertEqual(rows[0]['Info'], 'Packet 1 Info')

        # Check second packet row
        self.assertEqual(rows[1]['No.'], '2')
        self.assertEqual(float(rows[1]['Time']), 5.0)
        self.assertEqual(rows[1]['Source'], '192.168.1.3')
        self.assertEqual(rows[1]['Destination'], '192.168.1.4')
        self.assertEqual(rows[1]['Protocol'], 'UDP')
        self.assertEqual(rows[1]['Length'], '200')
        self.assertEqual(rows[1]['Info'], 'Packet 2 Info')

if __name__ == '__main__':
    unittest.main()
