import requests
import time
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

VT_UPLOAD_URL = "https://www.virustotal.com/vtapi/v2/file/scan"
VT_REPORT_URL = "https://www.virustotal.com/vtapi/v2/file/report"


def upload_to_virustotal(file_path: Path, api_key: str):
    """Sube archivo a VirusTotal"""
    try:
        logger.debug(f"Subiendo archivo a VirusTotal: {file_path.name}")
        print(f"      [+] Subiendo a VirusTotal...")

        with open(file_path, 'rb') as file:
            files = {'file': (file_path.name, file)}
            params = {'apikey': api_key}
            response = requests.post(VT_UPLOAD_URL, files=files, params=params, timeout=30)

        if response.status_code == 200:
            result = response.json()
            scan_id = result.get('scan_id')
            logger.info(f"Archivo subido exitosamente. Scan ID: {scan_id}")
            return scan_id
        else:
            logger.error(f"Error al subir archivo: HTTP {response.status_code} - {response.text}")
            print(f"      [+] Error upload: {response.status_code}")
            return None

    except requests.exceptions.Timeout:
        logger.error(f"Timeout al subir archivo {file_path.name}")
        print(f"      [+] Timeout al subir archivo")
        return None
    except requests.exceptions.RequestException as e:
        logger.error(f"Error de conexión al subir archivo: {e}")
        print(f"      [+] Error de conexión: {e}")
        return None
    except Exception as e:
        logger.exception(f"Excepción inesperada al subir archivo: {e}")
        print(f"      [+] Exception upload: {e}")
        return None


def get_virustotal_report(scan_id: str, api_key: str):
    """Obtiene reporte de VirusTotal"""
    max_retries = 6

    for attempt in range(max_retries):
        try:
            logger.debug(f"Obteniendo reporte de VirusTotal (intento {attempt + 1}/{max_retries})")
            print(f"      [+] Esperando VT ({attempt + 1}/{max_retries})...")
            time.sleep(20)  # Tiempo para análisis de VirusTotal

            params = {'apikey': api_key, 'resource': scan_id}
            response = requests.get(VT_REPORT_URL, params=params, timeout=30)

            if response.status_code == 200:
                result = response.json()
                response_code = result.get('response_code', 0)

                if response_code == 1:
                    positives = result.get('positives', 0)
                    total = result.get('total', 1)
                    ratio = positives / max(total, 1)

                    logger.info(f"Reporte obtenido: {positives}/{total} detectado (ratio: {ratio:.3f})")
                    print(f"      [+] VT Result: {positives}/{total}")

                    return {
                        'positives': positives,
                        'total': total,
                        'ratio': ratio
                    }
                elif response_code == -2:
                    logger.debug("Análisis aún en progreso, reintentando...")
                    continue
                else:
                    logger.warning(f"Respuesta inesperada de VirusTotal: response_code={response_code}")
                    if attempt < max_retries - 1:
                        continue
            else:
                logger.error(f"Error HTTP al obtener reporte: {response.status_code} - {response.text}")
                if attempt < max_retries - 1:
                    continue

        except requests.exceptions.Timeout:
            logger.warning(f"Timeout al obtener reporte (intento {attempt + 1})")
            if attempt < max_retries - 1:
                continue
            break
        except requests.exceptions.RequestException as e:
            logger.error(f"Error de conexión al obtener reporte: {e}")
            if attempt < max_retries - 1:
                continue
            break
        except Exception as e:
            logger.exception(f"Excepción inesperada al obtener reporte: {e}")
            print(f"      [+] Exception report: {e}")
            break

    logger.error(f"No se pudo obtener reporte después de {max_retries} intentos")
    return None
