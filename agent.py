import json
import os
import random
import time
import logging

logger = logging.getLogger(__name__)


class FixedRLAgent:
    """RL Agent con mutaciones que SÍ se aplican"""

    def __init__(self, api_key, learning_rate, exploration_rate, discount_factor):
        self.vt_api_key = api_key
        self.q_table = {}
        self.learning_rate = learning_rate
        self.exploration_rate = exploration_rate
        self.discount_factor = discount_factor

        # Acciones MÁS AGRESIVAS que realmente cambian el código
        self.actions = [
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

        self.mutation_history = []

    def get_state(self, payload_hash, detection_ratio, payload_features=None):
        """
        Genera representación de estado mejorada usando features del payload.
        
        Args:
            payload_hash: Hash del payload (primeros 10 caracteres)
            detection_ratio: Ratio de detección (0.0-1.0)
            payload_features: Diccionario con features del payload (opcional)
                - variables: número de variables
                - methods: número de métodos
                - lines: número de líneas
                - has_base64: si contiene Base64
                - has_reflection: si usa reflexión
        
        Returns:
            String que representa el estado
        """
        # Discretizar ratio de detección (0-20 bins)
        ratio_bin = int(detection_ratio * 20)
        
        if payload_features:
            # Usar features para crear estado más rico
            var_bin = min(int(payload_features.get('variables', 0) / 5), 4)  # 0-4 bins
            method_bin = min(int(payload_features.get('methods', 0) / 3), 4)  # 0-4 bins
            line_bin = min(int(payload_features.get('lines', 0) / 10), 4)  # 0-4 bins
            has_base64 = 1 if payload_features.get('has_base64', False) else 0
            has_reflection = 1 if payload_features.get('has_reflection', False) else 0
            
            # Estado: hash_ratio_var_method_line_base64_reflection
            state = f"{payload_hash[:8]}_{ratio_bin}_{var_bin}_{method_bin}_{line_bin}_{has_base64}_{has_reflection}"
        else:
            # Fallback al método original si no hay features
            state = f"{payload_hash[:10]}_{ratio_bin}"
        
        return state

    def choose_action(self, state):
        if state not in self.q_table:
            self.q_table[state] = {action: 1.0 for action in self.actions}

        if random.random() < self.exploration_rate:
            action = random.choice(self.actions)
        else:
            action = max(self.q_table[state].items(), key=lambda x: x[1])[0]

        return action

    def update_q_value(self, state, action, reward, next_state):
        if state not in self.q_table:
            self.q_table[state] = {action: 1.0 for action in self.actions}
        if next_state not in self.q_table:
            self.q_table[next_state] = {action: 1.0 for action in self.actions}

        current_q = self.q_table[state][action]
        max_next_q = max(self.q_table[next_state].values())
        new_q = current_q + self.learning_rate * (reward + self.discount_factor * max_next_q - current_q)
        self.q_table[state][action] = new_q

        logger.debug(f"Q-value actualizado: estado={state}, acción={action}, "
                    f"Q_old={current_q:.3f}, Q_new={new_q:.3f}, reward={reward:.2f}")

        # Registrar mutación exitosa
        if reward > 0:
            self.mutation_history.append({
                'action': action,
                'reward': reward,
                'state': state,
                'timestamp': time.time()
            })
            logger.debug(f"Mutación exitosa registrada: {action} con reward {reward:.2f}")

    def load_q_table(self, file_path):
        """Carga la tabla Q desde un archivo JSON."""
        if os.path.exists(file_path):
            logger.info(f"Cargando tabla Q desde {file_path}")
            print(f"[+] Cargando tabla Q desde {file_path}")
            try:
                with open(file_path, 'r') as f:
                    self.q_table = json.load(f)
                logger.info(f"Tabla Q cargada: {len(self.q_table)} estados")
            except (json.JSONDecodeError, IOError) as e:
                logger.error(f"Error al cargar tabla Q: {e}. Se creará una nueva.")
                self.q_table = {}
        else:
            logger.info("No se encontró tabla Q existente, se creará una nueva.")
            print("[+] No se encontró tabla Q existente, se creará una nueva.")

    def save_q_table(self, file_path):
        """Guarda la tabla Q en un archivo JSON."""
        logger.info(f"Guardando tabla Q en {file_path} ({len(self.q_table)} estados)")
        print(f"[+] Guardando tabla Q en {file_path}")
        try:
            with open(file_path, 'w') as f:
                json.dump(self.q_table, f, indent=2)
            logger.info("Tabla Q guardada exitosamente")
        except IOError as e:
            logger.error(f"Error al guardar tabla Q: {e}")
            raise
