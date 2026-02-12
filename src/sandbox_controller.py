from pathlib import Path
from execution_engine import ExecutionEngine

class SandboxController:
    def run_sample(self, sample_path: Path):
        if not self._is_valid_sample(sample_path):
            return False
        
        print("-"*100)
        print(f"\n[*] Regress filtering started for: {sample_path.name}\n")
        
        try:
            with ExecutionEngine(sample_path) as engine:
                engine.run_analysis(runtime_sec=30)

            return True
        
        except Exception as e:
            print(f"[!] Regress filtering failed: {e}")
            return False

    def _is_valid_sample(self, path: Path):
        if not path.exists() or not path.is_file():
            print(f"[!] File not found or invalid: {path}")
            return False
        if path.suffix.lower() != '.py':
            print(f"[!] Invalid file type: {path.suffix}. Only .py files are supported.")
            return False
        if path.stat().st_size == 0:
            print(f"[!] File is empty: {path}")
            return False
        return True
    