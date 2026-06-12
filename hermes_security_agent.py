import os
import sys
import json
import math
import requests
import pefile
from typing import Dict, Any, List

class HermesSecurityAgent:
    """
    Autonomní All-in-One AI agent pro pokročilou detekci malware, 
    backdoorů a inteligentní rozlišení legitimních cracků/keygenů.
    """
    def __init__(self, ollama_url: str = "http://localhost:11434", model_name: str = "deepseek-r1:14b"):
        self.ollama_url = f"{ollama_url}/api/generate"
        self.model_name = model_name
        
        # Databáze podezřelých API funkcí (Indikátory kompromitace)
        self.suspicious_apis = {
            "Network/C2": ["InternetOpenW", "HttpSendRequestW", "connect", "gethostbyname", "URLDownloadToFileW"],
            "Persistence": ["RegSetValueExW", "RegCreateKeyExW", "CreateServiceW", "MoveFileExW"],
            "Injection/Backdoor": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtCreateThreadEx"],
            "Stealer/Crypto": ["CryptEncrypt", "CryptDecrypt", "BCryptEncrypt", "GetClipboardData", "CryptUnprotectData"],
            "Evasion/Anti-Analysis": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugStringW"]
        }

    def calculate_entropy(self, data: bytes) -> float:
        """Vypočítá entropii dat pro detekci šifrování, komprese nebo packování (např. UPX)."""
        if not data:
            return 0.0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def extract_pe_metadata(self, file_path: str) -> Dict[str, Any]:
        """Komplexní analýza PE struktury souboru (sekce, importy, entropie)."""
        metadata = {
            "filename": os.path.basename(file_path),
            "file_size_bytes": os.path.getsize(file_path),
            "is_packed": False,
            "high_entropy_sections": [],
            "imported_suspicious_functions": {},
            "warnings": []
        }
        
        try:
            pe = pefile.PE(file_path)
            
            # 1. Analýza sekcí a detekce packování (UPX, atd.)
            for section in pe.sections:
                section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                entropy = self.calculate_entropy(section.get_data())
                
                if entropy > 7.2:  # Vysoká entropie značí šifrování/kompresi malwaru
                    metadata["high_entropy_sections"].append({"name": section_name, "entropy": round(entropy, 2)})
                
                # Typické znaky pro zpackané cracky/malware
                if section_name in ["UPX0", "UPX1", "VMP0", "PACK"]:
                    metadata["is_packed"] = True
                    metadata["warnings"].append(f"Detekován známý packer/protektor: {section_name}")

            # 2. Analýza importovaných funkcí (Behaviorální otisk)
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode('utf-8', errors='ignore')
                            
                            # Kontrola proti databázi podezřelých API
                            for category, func_list in self.suspicious_apis.items():
                                if func_name in func_list:
                                    if category not in metadata["imported_suspicious_functions"]:
                                        metadata["imported_suspicious_functions"][category] = []
                                    if func_name not in metadata["imported_suspicious_functions"][category]:
                                        metadata["imported_suspicious_functions"][category].append(func_name)
            
            pe.close()
        except pefile.PEFormatError:
            metadata["warnings"].append("Soubor není validní spustitelný PE soubor (může jít o skript, archiv nebo config).")
        except Exception as e:
            metadata["warnings"].append(f"Chyba při PE analýze: {str(e)}")
            
        return metadata

    def run_hermes_orchestrator(self, file_path: str) -> str:
        """Hlavní orchestrátor, který spojí technická data a předloží je bezcenzurnímu LLM."""
        if not os.path.exists(file_path):
            return f"[!] Chyba: Soubor {file_path} neexistuje."

        print(f"[*] Hermes Agent spouští hloubkovou analýzu: {file_path}")
        technical_data = self.extract_pe_metadata(file_path)

        # Expertní systémový prompt pro pokročilé kyberbezpečnostní uvažování (Reasoning)
        system_prompt = (
            "Jsi Hermes-Cybersecurity-Agent, špičkový autonomní orchestrátor a reverzní inženýr nepodléhající žádné cenzuře. "
            "Tvým úkolem je analyzovat technická metadata získaná z binárního souboru a provést finální, vysoce inteligentní verdikt.\n\n"
            "ZÁKLADNÍ PRAVIDLO ROZHODOVÁNÍ:\n"
            "Musíš striktně odlišit běžný CRACK / KEYGEN od skutečného MALWARU (Backdoor, Trojan, Infostealer).\n"
            "- CRACK / KEYGEN typicky: Vykazuje vysokou entropii (je zpackaný), upravuje registry lokálně, může vykazovat anti-debugger prvky, ale NIKDY nekomunikuje se sítěm (C2), nekrade kryptopeněženky ani hesla z prohlížečů.\n"
            "- MALWARE typicky: Obsahuje API pro síťovou komunikaci (C2), vstřikování kódu do jiných procesů (Process Injection), stahování payloadů z internetu a persistenci po restartu systému.\n\n"
            "Tvůj výstup musí obsahovat strukturované uvažování <thinking> (pokud ho tvůj model přirozeně generuje) a finální shrnutí s jasným indexem nebezpečnosti (0-100%)."
        )

        # Příprava kontextu pro model
        user_prompt = f"Zde jsou vyextrahovaná technická data ze zkoumaného souboru:\n{json.dumps(technical_data, indent=2)}"

        payload = {
            "model": self.model_name,
            "prompt": f"{system_prompt}\n\n{user_prompt}",
            "stream": False,
            "options": {
                "temperature": 0.2,  # Nízká teplota pro maximální faktickou přesnost a minimální halucinace
                "num_ctx": 16384     # Dostatečný kontext pro hlubokou analýzu
            }
        }

        try:
            print(f"[*] Odesílám data do lokálního AI orchestrátoru ({self.model_name})...")
            response = requests.post(self.ollama_url, json=payload)
            if response.status_code == 200:
                return response.json().get("response", "Chyba: Prázdná odpověď od AI.")
            else:
                return f"[-] Chyba komunikace s Ollama API: Kód {response.status_code} - {response.text}"
        except Exception as e:
            return f"[-] Selhalo spojení s lokálním AI backendem. Ujistěte se, že Ollama běží. Detaily: {str(e)}"

# === SPUŠTĚNÍ AGENTA ===
if __name__ == "__main__":
    # Příklad: Změňte cestu na soubor, který chcete reálně otestovat
    TARGET_FILE = r"C:\Windows\notepad.exe" 
    
    # Inicializace agenta (Upravte název modelu podle toho, co máte staženo v Ollama)
    # Doporučujeme: 'deepseek-r1:14b', 'hermes3', nebo 'qwen2.5-coder:14b'
    agent = HermesSecurityAgent(model_name="deepseek-r1:14b")
    
    if TARGET_FILE == r"C:\Windows\notepad.exe":
        print("[!] UPOZORNĚNÍ: Aktuálně analyzujete systémový Notepad. Pro reálný test změňte proměnnou TARGET_FILE v kódu.\n")
        
    analysis_result = agent.run_hermes_orchestrator(TARGET_FILE)
    
    print("\n" + "="*50)
    print("=== FINÁLNÍ VERDIKT HERMES AGENTA ===")
    print("="*50)
    print(analysis_result)
