"""
Tests unitarios para el módulo agent.py
"""
import unittest
import os
import json
import tempfile
from agent import FixedRLAgent


class TestFixedRLAgent(unittest.TestCase):
    """Tests para el agente RL"""

    def setUp(self):
        """Setup: crear agente de prueba"""
        self.agent = FixedRLAgent(
            api_key="test_key",
            learning_rate=0.3,
            exploration_rate=0.4,
            discount_factor=0.9
        )

    def test_agent_initialization(self):
        """Test: inicialización del agente"""
        self.assertEqual(self.agent.learning_rate, 0.3)
        self.assertEqual(self.agent.exploration_rate, 0.4)
        self.assertEqual(self.agent.discount_factor, 0.9)
        self.assertEqual(len(self.agent.actions), 10)
        self.assertIsInstance(self.agent.q_table, dict)

    def test_get_state_without_features(self):
        """Test: generación de estado sin features"""
        state = self.agent.get_state("abc1234567", 0.5)
        self.assertIsInstance(state, str)
        self.assertIn("abc123456", state)
        self.assertIn("10", state)  # ratio_bin = 0.5 * 20 = 10

    def test_get_state_with_features(self):
        """Test: generación de estado con features"""
        features = {
            'variables': 5,
            'methods': 3,
            'lines': 15,
            'has_base64': True,
            'has_reflection': False
        }
        state = self.agent.get_state("abc1234567", 0.5, features)
        self.assertIsInstance(state, str)
        # Estado debería incluir todos los componentes
        parts = state.split('_')
        self.assertGreaterEqual(len(parts), 5)

    def test_choose_action_exploration(self):
        """Test: elección de acción con exploración"""
        state = "test_state_10"
        # Con alta exploración, debería elegir acción aleatoria
        action = self.agent.choose_action(state)
        self.assertIn(action, self.agent.actions)

    def test_choose_action_exploitation(self):
        """Test: elección de acción con explotación"""
        state = "test_state_10"
        # Inicializar Q-table con valores conocidos
        self.agent.q_table[state] = {
            'encode_all_strings_base64': 2.0,
            'split_commands_aggressive': 1.0,
            'rename_all_variables': 1.5,
            'add_multiple_benign_wrappers': 1.0,
            'change_entire_syntax': 1.0,
            'insert_random_whitespace': 1.0,
            'obfuscate_network_calls': 1.0,
            'use_reflection_methods': 1.0,
            'add_fake_error_handling': 1.0,
            'modify_encoding_methods': 1.0
        }
        
        # Con exploración deshabilitada, debería elegir la mejor
        original_exploration = self.agent.exploration_rate
        self.agent.exploration_rate = 0.0
        action = self.agent.choose_action(state)
        self.assertEqual(action, 'encode_all_strings_base64')
        self.agent.exploration_rate = original_exploration

    def test_update_q_value(self):
        """Test: actualización de Q-value"""
        state = "test_state_10"
        next_state = "test_state_5"
        action = 'encode_all_strings_base64'
        reward = 1.5
        
        # Inicializar estados
        self.agent.q_table[state] = {a: 1.0 for a in self.agent.actions}
        self.agent.q_table[next_state] = {a: 1.0 for a in self.agent.actions}
        
        old_q = self.agent.q_table[state][action]
        self.agent.update_q_value(state, action, reward, next_state)
        new_q = self.agent.q_table[state][action]
        
        # Q-value debería haber cambiado
        self.assertNotEqual(old_q, new_q)
        # Con reward positivo, Q debería aumentar
        self.assertGreater(new_q, old_q)

    def test_save_and_load_q_table(self):
        """Test: guardar y cargar tabla Q"""
        # Crear tabla Q de prueba
        test_state = "test_state_10"
        self.agent.q_table[test_state] = {a: 1.5 for a in self.agent.actions}
        
        # Guardar en archivo temporal
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            temp_path = f.name
        
        try:
            self.agent.save_q_table(temp_path)
            self.assertTrue(os.path.exists(temp_path))
            
            # Crear nuevo agente y cargar
            new_agent = FixedRLAgent("test_key", 0.3, 0.4, 0.9)
            new_agent.load_q_table(temp_path)
            
            # Verificar que se cargó correctamente
            self.assertIn(test_state, new_agent.q_table)
            self.assertEqual(
                new_agent.q_table[test_state]['encode_all_strings_base64'],
                1.5
            )
        finally:
            # Limpiar archivo temporal
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_mutation_history(self):
        """Test: historial de mutaciones"""
        state = "test_state_10"
        next_state = "test_state_5"
        action = 'encode_all_strings_base64'
        reward = 2.0
        
        self.agent.q_table[state] = {a: 1.0 for a in self.agent.actions}
        self.agent.q_table[next_state] = {a: 1.0 for a in self.agent.actions}
        
        initial_history_len = len(self.agent.mutation_history)
        self.agent.update_q_value(state, action, reward, next_state)
        
        # Con reward positivo, debería añadirse al historial
        self.assertGreater(len(self.agent.mutation_history), initial_history_len)
        self.assertEqual(self.agent.mutation_history[-1]['action'], action)
        self.assertEqual(self.agent.mutation_history[-1]['reward'], reward)


if __name__ == '__main__':
    unittest.main()

