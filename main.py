import hashlib
import os
import time
import json
import logging
from pathlib import Path
from datetime import datetime

from agent import FixedRLAgent
from mutations import apply_aggressive_mutation, analyze_payload_detailed, validate_mutation_applied
from virustotal import upload_to_virustotal, get_virustotal_report

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'evolution_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


def load_config():
    """
    Carga la configuración desde config.json.
    
    Returns:
        dict: Configuración cargada desde el archivo
        
    Raises:
        SystemExit: Si el archivo no existe o no es JSON válido
    """
    try:
        with open("config.json", 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        # Validar estructura básica de configuración
        required_sections = ['virustotal', 'agent', 'evolution', 'agent_persistence']
        for section in required_sections:
            if section not in config:
                logger.error(f"Sección requerida '{section}' no encontrada en config.json")
                print(f"[!] Error: Sección requerida '{section}' no encontrada en config.json")
                exit(1)
        
        # Validar que existe api_key
        if 'api_key' not in config.get('virustotal', {}):
            logger.error("API key de VirusTotal no encontrada en config.json")
            print("[!] Error: API key de VirusTotal no encontrada en config.json")
            exit(1)
        
        logger.info("Configuración cargada exitosamente")
        return config
        
    except FileNotFoundError:
        logger.error("Archivo config.json no encontrado")
        print("[!] Error: config.json no encontrado.")
        print("[!] Por favor, crea un archivo config.json con la estructura adecuada.")
        exit(1)
    except json.JSONDecodeError as e:
        logger.error(f"Error al parsear config.json: {e}")
        print(f"[!] Error: config.json no es un archivo JSON válido: {e}")
        exit(1)
    except PermissionError:
        logger.error("Sin permisos para leer config.json")
        print("[!] Error: Sin permisos para leer config.json")
        exit(1)
    except Exception as e:
        logger.exception(f"Error inesperado al cargar configuración: {e}")
        print(f"[!] Error inesperado: {e}")
        exit(1)


def run_fixed_rl_evolution(config):
    """Ejecuta evolución RL con mutaciones FIJAS"""

    vt_api_key = config['virustotal']['api_key']
    agent_config = config['agent']
    evo_config = config['evolution']
    persistence_config = config['agent_persistence']
    q_table_path = persistence_config['q_table_path']

    if vt_api_key == "TU_API_KEY_DE_VIRUSTOTAL_AQUI":
        logger.error("API key de VirusTotal no configurada. Por favor, añade tu API key en config.json")
        return

    output_dir = Path("fixed_mutations_output")
    output_dir.mkdir(exist_ok=True)

    # Cargar payloads desde archivo
    if not os.path.exists("payloads.txt"):
        logger.error("Archivo payloads.txt no encontrado")
        print("[+] No se encuentra payloads.txt")
        return

    try:
        with open("payloads.txt", 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Dividir payloads por separadores (--- o ===) o líneas vacías múltiples
        # Si no hay separadores, tratar todo el archivo como un solo payload
        if '---' in content or '===' in content:
            # Separar por marcadores explícitos
            separators = ['---', '===']
            for sep in separators:
                if sep in content:
                    raw_payloads = content.split(sep)
                    break
        else:
            # Si no hay separadores, tratar todo como un payload
            raw_payloads = [content]
        
        # Procesar cada payload: limpiar líneas de comentarios y espacios
        payloads = []
        for raw_payload in raw_payloads:
            # Dividir en líneas, filtrar comentarios y líneas vacías
            lines = []
            for line in raw_payload.split('\n'):
                stripped = line.strip()
                # Ignorar líneas vacías y comentarios
                if stripped and not stripped.startswith('#'):
                    lines.append(line.rstrip())
            
            # Unir líneas en un payload completo
            if lines:
                payload = '\n'.join(lines)
                # Solo añadir si el payload tiene contenido significativo
                if len(payload.strip()) > 10:  # Mínimo 10 caracteres
                    payloads.append(payload)
        
        if not payloads:
            logger.warning("Archivo payloads.txt está vacío o no contiene payloads válidos")
            print("[!] Advertencia: payloads.txt está vacío o no contiene payloads válidos")
            return
    except PermissionError:
        logger.error("Sin permisos para leer payloads.txt")
        print("[!] Error: Sin permisos para leer payloads.txt")
        return
    except Exception as e:
        logger.exception(f"Error al leer payloads.txt: {e}")
        print(f"[!] Error al leer payloads.txt: {e}")
        return

    logger.info(f"Cargados {len(payloads)} payloads desde archivo")
    print(f"[+] CARGADOS {len(payloads)} PAYLOADS DESDE ARCHIVO")
    print("=" * 60)

    # --- Crear y cargar agente RL ---
    rl_agent = FixedRLAgent(
        api_key=vt_api_key,
        learning_rate=agent_config['learning_rate'],
        exploration_rate=agent_config['exploration_rate'],
        discount_factor=agent_config['discount_factor']
    )
    rl_agent.load_q_table(q_table_path)
    logger.info(f"Agente RL inicializado. Estados en Q-table: {len(rl_agent.q_table)}")
    # --------------------------------

    for i, original_payload in enumerate(payloads):
        logger.info(f"Procesando payload {i + 1}/{len(payloads)}")
        print(f"\n[+] PROCESANDO PAYLOAD {i + 1}/{len(payloads)}")
        print(f"   Original: {original_payload[:100]}...")

        # Analizar payload original
        original_analysis = analyze_payload_detailed(original_payload)
        logger.info(f"Análisis payload {i + 1}: {len(original_analysis['variables'])} variables, "
                   f"{len(original_analysis['methods'])} métodos, {original_analysis['lines']} líneas")
        print(f"   [+] Análisis: {len(original_analysis['variables'])} variables, {len(original_analysis['methods'])} métodos")

        best_payload = original_payload
        best_ratio = 1.0

        # Evaluar payload original
        original_file = output_dir / f"payload_{i:02d}_original.ps1"
        try:
            with open(original_file, 'w', encoding='utf-8') as f:
                f.write(original_payload)
        except IOError as e:
            logger.error(f"Error al guardar payload original {i + 1}: {e}")
            print(f"[!] Error al guardar payload original: {e}")
            continue

        logger.info(f"Evaluando payload original {i + 1}")
        print("   [+] Evaluando payload original...")
        original_scan_id = upload_to_virustotal(original_file, vt_api_key)
        if original_scan_id:
            vt_result = get_virustotal_report(original_scan_id, vt_api_key)
            if vt_result:
                best_ratio = vt_result['ratio']
                logger.info(f"Payload original {i + 1}: {vt_result['positives']}/{vt_result['total']} "
                          f"detectado (ratio: {best_ratio:.3f})")
                print(f"   [+] ORIGINAL: {vt_result['positives']}/{vt_result['total']} ({best_ratio:.3f})")
            else:
                logger.warning(f"No se pudo obtener resultado de VirusTotal para payload original {i + 1}")
        else:
            logger.error(f"No se pudo subir payload original {i + 1} a VirusTotal")

        # Evolución RL
        for generation in range(1, evo_config['generations'] + 1):
            print(f"\n   [+] GENERACIÓN {generation}/{evo_config['generations']}")

            for variant in range(1, evo_config['variants_per_generation'] + 1):
                print(f"\n      [+] VARIANTE {variant}/{evo_config['variants_per_generation']}")

                # Analizar payload actual para extraer features
                current_analysis = analyze_payload_detailed(best_payload)
                payload_features = {
                    'variables': len(current_analysis['variables']),
                    'methods': len(current_analysis['methods']),
                    'lines': current_analysis['lines'],
                    'has_base64': 'Base64' in best_payload or 'base64' in best_payload.lower(),
                    'has_reflection': '.GetType()' in best_payload or '.GetMethod(' in best_payload
                }

                # Estado actual con features mejoradas
                payload_hash = hashlib.md5(best_payload.encode()).hexdigest()
                current_state = rl_agent.get_state(
                    payload_hash,
                    best_ratio,
                    payload_features
                )

                # Elegir acción
                action = rl_agent.choose_action(current_state)
                logger.debug(f"Payload {i + 1}, Gen {generation}, Var {variant}: Acción elegida: {action}, "
                           f"Estado: {current_state}, Exploración: {rl_agent.exploration_rate:.3f}")
                print(f"      [+] Acción RL: {action}")
                print(f"      [+] Exploración: {rl_agent.exploration_rate:.3f}")

                # Aplicar mutación AGRESIVA
                mutated_payload = apply_aggressive_mutation(best_payload, action, f"{i}_{generation}_{variant}")

                # Validar que la mutación se aplicó
                is_mutated, mutation_message = validate_mutation_applied(best_payload, mutated_payload)

                if not is_mutated:
                    logger.warning(f"Mutación falló para payload {i + 1}, gen {generation}, var {variant}: {mutation_message}")
                    print(f"      [+] Mutación falló: {mutation_message}")
                    continue

                logger.info(f"Mutación aplicada exitosamente: {action} - {mutation_message}")
                print(f"      [+] Mutación aplicada: {mutation_message}")

                # Guardar variante
                variant_hash = hashlib.md5(mutated_payload.encode()).hexdigest()[:12]
                variant_file = output_dir / f"payload_{i:02d}_gen{generation}_var{variant}_{variant_hash}.ps1"

                try:
                    with open(variant_file, 'w', encoding='utf-8') as f:
                        f.write(mutated_payload)
                except IOError as e:
                    logger.error(f"Error al guardar variante: {e}")
                    print(f"      [+] Error al guardar variante: {e}")
                    continue

                # Subir a VirusTotal
                scan_id = upload_to_virustotal(variant_file, vt_api_key)

                if scan_id:
                    vt_result = get_virustotal_report(scan_id, vt_api_key)

                    if vt_result:
                        detection_ratio = vt_result['ratio']

                        # Calcular recompensa
                        reward = (best_ratio - detection_ratio) * 15

                        # Analizar payload mutado para features del siguiente estado
                        mutated_analysis = analyze_payload_detailed(mutated_payload)
                        next_payload_features = {
                            'variables': len(mutated_analysis['variables']),
                            'methods': len(mutated_analysis['methods']),
                            'lines': mutated_analysis['lines'],
                            'has_base64': 'Base64' in mutated_payload or 'base64' in mutated_payload.lower(),
                            'has_reflection': '.GetType()' in mutated_payload or '.GetMethod(' in mutated_payload
                        }

                        # Actualizar RL con estado siguiente mejorado
                        next_state = rl_agent.get_state(variant_hash, detection_ratio, next_payload_features)
                        rl_agent.update_q_value(current_state, action, reward, next_state)

                        logger.info(f"Payload {i + 1}, Gen {generation}, Var {variant}: "
                                  f"{vt_result['positives']}/{vt_result['total']} detectado "
                                  f"(ratio: {detection_ratio:.3f}, reward: {reward:.2f})")
                        print(
                            f"      [+] Resultado: {vt_result['positives']}/{vt_result['total']} (ratio: {detection_ratio:.3f})")
                        print(f"      [+] Recompensa: {reward:.2f}")

                        # Actualizar mejor
                        if detection_ratio < best_ratio:
                            improvement = (best_ratio - detection_ratio) * 100
                            best_ratio = detection_ratio
                            best_payload = mutated_payload
                            logger.info(f"NUEVO MEJOR payload {i + 1}: {improvement:.1f}% de mejora "
                                      f"(ratio: {best_ratio:.3f})")
                            print(f"      [+] NUEVO MEJOR: {improvement:.1f}% de mejora")
                    else:
                        logger.warning(f"No se pudo obtener resultado de VirusTotal para payload {i + 1}, "
                                     f"gen {generation}, var {variant}")
                else:
                    logger.error(f"No se pudo subir variante a VirusTotal: payload {i + 1}, "
                               f"gen {generation}, var {variant}")

                time.sleep(18)  # Rate limiting (VirusTotal free tier: 4 req/min = 15s min)

        # Guardar mejor payload
        best_file = output_dir / f"payload_{i:02d}_best.ps1"
        try:
            with open(best_file, 'w', encoding='utf-8') as f:
                f.write(best_payload)
        except IOError as e:
            logger.error(f"Error al guardar mejor payload {i + 1}: {e}")
            print(f"[!] Error al guardar mejor payload: {e}")

        logger.info(f"Mejor payload {i + 1} guardado: {best_file} (ratio final: {best_ratio:.3f})")
        print(f"\n   [+] Mejor payload guardado: {best_file}")

        # Mostrar historial de mutaciones exitosas
        if rl_agent.mutation_history:
            logger.info(f"Mutaciones exitosas para payload {i + 1}: {len(rl_agent.mutation_history)}")
            print(f"   [+] Mutaciones exitosas: {len(rl_agent.mutation_history)}")
            for mutation in rl_agent.mutation_history[-3:]:  # Últimas 3
                print(f"      [+] {mutation['action']}: reward {mutation['reward']:.2f}")

    # --- Guardar el estado del agente ---
    rl_agent.save_q_table(q_table_path)
    logger.info(f"Tabla Q guardada con {len(rl_agent.q_table)} estados")
    # ------------------------------------

    logger.info("Evolución completada")
    print(f"\n[+] EVOLUCIÓN COMPLETADA")
    print("=" * 50)
    print("[+] Revisa los archivos en: fixed_mutations_output/")
    print("[+] Compara los payloads originales vs mutados")


def main():
    """Función principal"""

    print("[+] ADVERSARIAL RL - MUTACIONES FIJAS")
    print("====================================")
    print("[+] Mutaciones AGRESIVAS que SÍ se aplican")
    print("[+] Técnicas: Base64, reflexión, wrappers, sintaxis")
    print("[+] Feedback real de VirusTotal")
    print("=" * 60)

    config = load_config()

    try:
        run_fixed_rl_evolution(config)
    except KeyboardInterrupt:
        logger.warning("Ejecución interrumpida por el usuario")
        print("\n[+] Ejecución interrumpida")
    except Exception as e:
        logger.exception(f"Error durante la evolución: {e}")
        print(f"\n[+] Error: {e}")
        import traceback
        traceback.print_exc()



if __name__ == "__main__":
    main()
