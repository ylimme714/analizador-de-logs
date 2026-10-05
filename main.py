import re
from collections import Counter
from datetime import datetime

# Configuración de umbral de detección
MAX_FAILED_ATTEMPTS = 5
LOG_FILE_PATH = "auth.log"

def analyze_logs(file_path):
    """
    Lee el archivo de log y extrae intentos fallidos de SSH usando expresiones regulares (Regex).
    """
    failed_ips = []
    
    # Expresión regular para capturar la IP en líneas con "Failed password"
    # Ejemplo de línea: Oct 05 10:15:22 server sshd[1234]: Failed password for invalid user root from 192.168.1.50 port 51234
    ip_pattern = r"Failed password for .* from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"

    print("-" * 65)
    print("      ANALIZADOR DE LOGS SSH - DETECCIÓN BRUTE FORCE         ")
    print("-" * 65)
    print(f"[*] Analizando archivo: {file_path}")
    print(f"[*] Umbral de alerta: > {MAX_FAILED_ATTEMPTS} intentos fallidos")
    print("-" * 65)

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            for line in file:
                match = re.search(ip_pattern, line)
                if match:
                    ip_address = match.group(1)
                    failed_ips.append(ip_address)
    except FileNotFoundError:
        print(f"[!] Error: No se encontró el archivo '{file_path}'.")
        print("    Asegúrate de crear un archivo 'auth.log' de prueba.")
        return

    # Contar la frecuencia de intentos por IP
    ip_counts = Counter(failed_ips)
    
    # Filtrar direcciones IP que superan el umbral
    suspicious_ips = {ip: count for ip, count in ip_counts.items() if count >= MAX_FAILED_ATTEMPTS}

    # Mostrar reporte en consola
    if suspicious_ips:
        print("\n🚨 ¡ALERTAS DE SEGURIDAD DETECTADAS!")
        print(f"{'Dirección IP Sospechosa':<25} | {'Intentos Fallidos':<18} | {'Estado'}")
        print("-" * 65)
        for ip, count in suspicious_ips.items():
            print(f"{ip:<25} | {count:<18} | 🛑 BLOQUEO RECOMENDADO")
        print("-" * 65)
        print(f"\nTotal de IP maliciosas identificadas: {len(suspicious_ips)}")
    else:
        print("\n✅ No se detectaron patrones de ataque que superen el umbral.")

if __name__ == "__main__":
    analyze_logs(LOG_FILE_PATH)
