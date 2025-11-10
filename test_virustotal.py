"""
Tests unitarios para el módulo virustotal.py
"""
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path
import tempfile
import os
from virustotal import upload_to_virustotal, get_virustotal_report


class TestVirusTotal(unittest.TestCase):
    """Tests para funciones de VirusTotal"""

    def setUp(self):
        """Setup: crear archivo temporal de prueba"""
        self.test_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.ps1', suffix='.txt')
        self.test_file.write('Test PowerShell payload')
        self.test_file.close()
        self.test_path = Path(self.test_file.name)
        self.api_key = "test_api_key"

    def tearDown(self):
        """Cleanup: eliminar archivo temporal"""
        if os.path.exists(self.test_path):
            os.remove(self.test_path)

    @patch('virustotal.requests.post')
    def test_upload_to_virustotal_success(self, mock_post):
        """Test: subida exitosa a VirusTotal"""
        # Mock de respuesta exitosa
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'scan_id': 'test_scan_id_12345'}
        mock_post.return_value = mock_response
        
        scan_id = upload_to_virustotal(self.test_path, self.api_key)
        
        self.assertEqual(scan_id, 'test_scan_id_12345')
        mock_post.assert_called_once()

    @patch('virustotal.requests.post')
    def test_upload_to_virustotal_error(self, mock_post):
        """Test: error al subir a VirusTotal"""
        # Mock de respuesta con error
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.text = 'Forbidden'
        mock_post.return_value = mock_response
        
        scan_id = upload_to_virustotal(self.test_path, self.api_key)
        
        self.assertIsNone(scan_id)

    @patch('virustotal.requests.post')
    def test_upload_to_virustotal_timeout(self, mock_post):
        """Test: timeout al subir"""
        import requests
        mock_post.side_effect = requests.exceptions.Timeout("Connection timeout")
        
        scan_id = upload_to_virustotal(self.test_path, self.api_key)
        
        self.assertIsNone(scan_id)

    @patch('virustotal.requests.get')
    @patch('virustotal.time.sleep')
    def test_get_virustotal_report_success(self, mock_sleep, mock_get):
        """Test: obtener reporte exitoso de VirusTotal"""
        # Mock de respuesta exitosa
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'response_code': 1,
            'positives': 5,
            'total': 60
        }
        mock_get.return_value = mock_response
        
        result = get_virustotal_report('test_scan_id', self.api_key)
        
        self.assertIsNotNone(result)
        self.assertEqual(result['positives'], 5)
        self.assertEqual(result['total'], 60)
        self.assertAlmostEqual(result['ratio'], 5/60, places=3)

    @patch('virustotal.requests.get')
    @patch('virustotal.time.sleep')
    def test_get_virustotal_report_pending(self, mock_sleep, mock_get):
        """Test: reporte aún en progreso"""
        # Mock de respuesta pendiente
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'response_code': -2  # Análisis en progreso
        }
        mock_get.return_value = mock_response
        
        result = get_virustotal_report('test_scan_id', self.api_key)
        
        # Debería reintentar y eventualmente retornar None
        self.assertIsNone(result)

    @patch('virustotal.requests.get')
    @patch('virustotal.time.sleep')
    def test_get_virustotal_report_timeout(self, mock_sleep, mock_get):
        """Test: timeout al obtener reporte"""
        import requests
        mock_get.side_effect = requests.exceptions.Timeout("Connection timeout")
        
        result = get_virustotal_report('test_scan_id', self.api_key)
        
        self.assertIsNone(result)


if __name__ == '__main__':
    unittest.main()

