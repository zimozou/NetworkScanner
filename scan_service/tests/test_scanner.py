import unittest
import sys
import os
from unittest.mock import patch, MagicMock

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.scanner import NetworkScanner

class TestNetworkScanner (unittest.TestCase):
    @patch('nmap.PortScanner')
    def test_basic_scan(self, mock_port_scanner):
        # Setup mock
        mock_instance = MagicMock()
        mock_port_scanner.return_value = mock_instance

        # Create sample scan data
        mock_instance.all_hosts.return_value = ["45.33.32.156"]
        mock_instance.__getitem__.return_value.state.return_value = "up"
        mock_instance.__getitem__.return_value.hostnames.return_value = [{"names": "test-host", "type": "PTR"}]
        mock_instance.__getitem__.return_value.all_protocols.return_value = ['tcp']
        mock_instance.__getitem__.return_value.getitem.return_value.keys.return_value = [22, 80]
        mock_instance.__getitem__.return_value.__getitem__.return_value.__getitem__.return_value = {
            'state': 'open',
            'name': 'ssh',
            'product': 'OpenSSH',
            'version': '7.2p2'
        }

        # Create scanner and run test
        scanner = NetworkScanner({})
        scan_id, results = scanner.scan('45.33.32.156', 'basic')

        #assetions
        self.assertIsNotNone(scan_id)
        self.assertEqual(results['target'], '45.33.32.156')
        self.assertEqual(results['scan_type'], 'basic')
        self.assertIn('45.33.32.156', results['hosts'])

        #Verify the scan was called with current arguments
        mock_instance.scan.assert_called_once_with('45.33.32.156', arguments='-sV -F --open')


if __name__ == '__main__':
    unittest.main()