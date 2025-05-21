import os
import json
import re
import requests
from collections import defaultdict
from ipaddress import ip_address, ip_network

class LogEntry:
    def __init__(self, ip, fecha, metodo, ruta, codigo):
        self.ip = ip
        self.fecha = fecha
        self.metodo = metodo
        self.ruta = ruta
        self.codigo = codigo

class IPGeoInfo:
    def __init__(self, ip):
        self.ip = ip
        self.country = "Desconocido"
        self.city = "Desconocido"
        self.fetch_geo()

    def is_public_ip(self):
        try:
            ip_obj = ip_address(self.ip)
            private_networks = [
                ip_network("10.0.0.0/8"),
                ip_network("172.16.0.0/12"),
                ip_network("192.168.0.0/16"),
                ip_network("127.0.0.0/8")
            ]
            return not any(ip_obj in net for net in private_networks)
        except ValueError:
            return False

    def fetch_geo(self):
        if not self.is_public_ip():
            print(f"[INFO] IP privada o inválida: {self.ip}")
            return

        try:
            response = requests.get(f"http://ip-api.com/json/{self.ip}", timeout=5)
            data = response.json()
            if data.get('status') == 'success':
                self.country = data.get('country', "Desconocido")
                self.city = data.get('city', "Desconocido")
            else:
                print(f"[WARN] Fallo API para IP {self.ip}: {data.get('message')}")
        except Exception as e:
            print(f"[ERROR] Error obteniendo geo para {self.ip}: {e}")

class LogProcessor:
    log_pattern = re.compile(r'(?P<ip>\d+\.\d+\.\d+\.\d+).*\[(?P<fecha>[^\]]+)\] "(?P<metodo>\w+) (?P<ruta>[^\s]+)[^"]*" (?P<codigo>\d{3})')

    def __init__(self, folder_path):
        self.folder_path = folder_path
        self.entries_by_ip = defaultdict(list)

    def process_logs(self):
        for file in os.listdir(self.folder_path):
            file_path = os.path.join(self.folder_path, file)
            if os.path.isfile(file_path):
                with open(file_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        match = self.log_pattern.search(line)
                        if match:
                            data = match.groupdict()
                            entry = LogEntry(
                                ip=data['ip'],
                                fecha=data['fecha'],
                                metodo=data['metodo'],
                                ruta=data['ruta'],
                                codigo=data['codigo']
                            )
                            self.entries_by_ip[entry.ip].append(entry)

    def build_result(self):
        results = []
        for ip, entries in self.entries_by_ip.items():
            geo = IPGeoInfo(ip)
            attack_list = [
                {
                    "fecha": e.fecha,
                    "metodo": e.metodo,
                    "ruta": e.ruta,
                    "codigo": e.codigo
                } for e in entries
            ]
            results.append({
                "country": geo.country,
                "city": geo.city,
                "attacks": attack_list
            })
        return results

    def print_and_save(self, results, output_file='output.json'):
        print(json.dumps(results, indent=4, ensure_ascii=False))
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=4, ensure_ascii=False)

if __name__ == "__main__":
    folder = r"C:\Users\Tatiana\Downloads\http"
    processor = LogProcessor(folder)
    processor.process_logs()
    results = processor.build_result()
    processor.print_and_save(results)
