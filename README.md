Este proyecto es una herramienta defensiva (Blue Team / SIEM) que analiza archivos de registros del sistema (logs de SSH o servidores web)
para detectar patrones sospechosos de intentos fallidos de inicio de sesión (Brute Force).

Cuando una dirección IP supera un umbral máximo de intentos fallidos (por ejemplo, más de 5 intentos), el script la identifica, 
calcula la frecuencia de los ataques y genera un reporte de alerta con las IP que deberían ser bloqueadas en el firewall.
