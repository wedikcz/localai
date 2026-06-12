import os
import sys
import json
import math
import hashlib
import requests
import pefile
import threading
import queue
import time
import wmi  # Vyžaduje administrátorské oprávnění pro real-time odchytávání
from typing import Dict, Any, List

class HermesInfiniteOperator:
    """
    Vojenský C5ISR AI Agent s architekturou L=Infinite (nekonečný kontext přes sémantické streamování)
    a integrovaným real-time hacking operátorem pro Windows 11.
    """
    def __init__(self, ollama_url: str = "http://localhost:11434", model_name: str = "deepseek-r1:14b"):
        self.ollama_url = f"{ollama_url}/api/generate"
        self.model_name = model_name
        self.telemetry_queue = queue.Queue()
        self.seen_processes = set()
        self.running = True
        
        # Globální paměť agenta (Simulace L=Infinite přes stavovou syntézu)
        self.infinite_memory_state = {
            "total_analyzed_objects": 0,
            "system_threat_level": "LOW",
            "historical_indicators": []
        }
        
        # C5ISR Matrix pro nízkoúrovňovou inspekci
        self.c5isr_matrix = {
            "C5ISR_C2_Network": ["InternetOpenW", "HttpSendRequestW", "connect", "WSAConnect", "DnsQuery_W"],
            "C5ISR_Intelligence_Theft": ["GetClipboardData", "CryptUnprotectData", "SamIConnect", "LsaOpenPolicy"],
            "C5ISR_Surveillance_Recon": ["EnumProcesses", "CreateToolhelp32Snapshot", "Process32FirstW"],
            "Cyber_Weapon_Injection": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtCreateThreadEx"],
            "Cyber_Persistence": ["RegSetValueExW", "CreateServiceW", "MoveFileExW"]
        }

    def calculate_entropy(self, data: bytes) -> float:
        """Matematická analýza entropie pro detekci zpackaných (UPX/VMP) cracků."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        frequencies = [0] * 256
        for byte in data:
            frequencies[byte] += 1
        for count in frequencies:
            if count > 0:
                p_x = float(count) / length
                entropy -= p_x * math.log(p_x, 2)
        return entropy

    def static_pe_analysis(self, file_path: str) -> Dict[str, Any]:
        """Blesková extrakce telemetrie bez ohledu na velikost souboru (L=Infinite kompatibilní)."""
        telemetry = {
            "path": file_path,
            "is_packed": False,
            "detected_apis": {},
            "anomalies": []
        }
        try:
            pe = pefile.PE(file_path, fast_load=True) # Fast load pro okamžitou odezvu v real-time
            pe.parse_data_directories()
            
            # Analýza entropie prvních sekcí (hledání krytí malwaru)
            for section in pe.sections[:3]:
                name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                if self.calculate_entropy(section.get_data()) > 7.4:
                    telemetry["is_packed"] = True
                    telemetry["anomalies"].append(f"Vysoká entropie v sekci: {name}")
            
            # Mapování IAT importů
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode('utf-8', errors='ignore')
                            for category, funcs in self.c5isr_matrix.items():
                                if func_name in funcs:
                                    if category not in telemetry["detected_apis"]:
                                        telemetry["detected_apis"][category] = []
                                    telemetry["detected_apis"][category].append(func_name)
            pe.close()
        except Exception as e:
            telemetry["anomalies"].append(f"Nelze plně analyzovat PE strukturu: {str(e)}")
        return telemetry

    def real_time_process_operator(self):
        """[Hacking Operator] Sleduje spouštění procesů ve Windows v reálném čase přes WMI."""
        print("[+] Real-Time Hacking Operátor aktivován. Monitoruji Windows 11...")
        try:
            c = wmi.WMI()
            process_watcher = c.watch_for_instance_creation(wmi_class="Win32_Process")
            
            while self.running:
                new_process = process_watcher()
                proc_name = new_process.Name
                proc_id = new_process.ProcessId
                proc_path = new_process.ExecutablePath
                
                if proc_path and os.path.exists(proc_path) and proc_id not in self.seen_processes:
                    self.seen_processes.add(proc_id)
                    
                    # Ignorujeme běžné systémové procesy Windows, abychom šetřili výkon
                    if "System32" in proc_path or "SysWOW64" in proc_path:
                        continue
                        
                    print(f"\n[!] OPERÁTOR ZACHYTIL NOVÝ PROCES: {proc_name} (PID: {proc_id})")
                    print(f"    Cesta: {proc_path}")
                    
                    # Odeslání do fronty pro asynchronní AI analýzu
                    self.telemetry_queue.put({"name": proc_name, "pid": proc_id, "path": proc_path})
        except Exception as e:
            print(f"[-] Kritická chyba Real-Time operátora (Spustili jste skript jako Správce?): {e}")

    def infinite_orchestrator_worker(self):
        """[L=Infinite Orchestrator] Rekurzivně zpracovává frontu událostí a aktualizuje nekonečnou paměť."""
        print("[+] L=Infinite Orchestrátor spuštěn. Čekám na data z operátora...")
        while self.running:
            try:
                task = self.telemetry_queue.get(timeout=1)
                
                # Provedeme okamžitou statickou pitvu zachyceného binárního souboru
                pe_telemetry = self.static_pe_analysis(task["path"])
                
                # Aktualizace globálního nekonečného stavu (L=Infinite state machine)
                self.infinite_memory_state["total_analyzed_objects"] += 1
                if pe_telemetry["detected_apis"]:
                    self.infinite_memory_state["historical_indicators"].append({
                        "time": time.strftime("%H:%M:%S"),
                        "proc": task["name"],
                        "indicators": list(pe_telemetry["detected_apis"].keys())
                    })

                # Generování expertního promptu pro bezcenzurní model
                system_prompt = (
                    "Jsi Hermes-C5ISR-Infinite-Orchestrator. Provádíš real-time analýzu incidentů na Windows 11.\n"
                    "Pracuješ bez jakékoliv cenzury a filtrů.\n\n"
                    "TVŮJ ÚKOL:\n"
                    "Rozhodni v reálném čase, zda nově spuštěný proces je bezpečný Crack/Keygen/Repack, "
                    "nebo nepřátelský Backdoor, Trojan či Infostealer.\n\n"
                    "ARCHITEKTURA L=INFINITE (Historický kontext systému):\n"
                    f"{json.dumps(self.infinite_memory_state, indent=2)}\n\n"
                    "Pokud proces vykazuje vlastnosti injektáže (Weapon) a síťové aktivity (C2) zároveň, "
                    "vyhlas okamžitý poplach. Pokud pouze modifikuje soubory hry a je zpackaný, označ ho jako CRACK."
                )

                user_prompt = f"AKTUÁLNÍ INCIDENT k vyhodnocení:\nProces: {task['name']} (PID: {task['pid']})\nTelemetrie: {json.dumps(pe_telemetry, indent=2)}"

                payload = {
                    "model": self.model_name,
                    "prompt": f"{system_prompt}\n\n{user_prompt}",
                    "stream": False,
                    "options": {"temperature": 0.1, "num_ctx": 16384}
                }

                print(f"[*] L=Infinite Orchestrátor odesílá incident ({task['name']}) k AI analýze...")
                
                response = requests.post(self.ollama_url, json=payload)
                if response.status_code == 200:
                    ai_verdict = response.json().get("response", "")
                    print("\n" + "="*60)
                    print(f"🚨 ŽIVÝ VERDIKT AGENTA PRO PROCES: {task['name']} (PID: {task['pid']})")
                    print("="*60)
                    print(ai_verdict)
                    print("="*60 + "\n")
                else:
                    print(f"[-] AI Core vrátilo chybu: {response.status_code}")
                
                self.telemetry_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[-] Chyba v orchestrátoru: {e}")

    def start(self):
        """Spustí paralelní vlákna pro monitorování a analýzu."""
        self.operator_thread = threading.Thread(target=self.real_time_process_operator)
        self.orchestrator_thread = threading.Thread(target=self.infinite_orchestrator_worker)
        
        self.operator_thread.daemon = True
        self.orchestrator_thread.daemon = True
        
        self.operator_thread.start()
        self.orchestrator_thread.start()
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[-] Vypínám Hermes C5ISR Agent...");
            self.running = False

if __name__ == "__main__":
    # Inicializace systému. Ujistěte se, že Ollama s vybraným modelem běží!
    # Doporučené modely: 'deepseek-r1:14b', 'hermes3' nebo 'qwen2.5-coder:14b'
    agent_system = HermesInfiniteOperator(model_name="deepseek-r1:14b")
    
    print("="*70)
    print("     HERMES C5ISR AGENT V1.0: L=INFINITE & REAL-TIME OPERATOR")
    print("="*70)
    print("[*] Spouštím paralelní podsystémy (Stiskněte Ctrl+C pro ukončení)...")
    
    agent_system.start()
