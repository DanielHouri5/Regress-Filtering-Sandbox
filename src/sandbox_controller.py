# src/sandbox_controller.py
from pathlib import Path
from src.execution_engine import ExecutionEngine

class SandboxController:
    def run_sample(self, sample_path: Path):
        # המרה לנתיב אבסולוטי בתוך הקונטיינר
        full_path = Path("/sandbox") / sample_path
        
        if not self._is_valid_sample(full_path):
            return False
        
        print("-" * 100)
        print(f"\n[*] Regress filtering started for: {full_path.name}\n")
        
        try:
            with ExecutionEngine(full_path) as engine:
                # הרצה ל-30 שניות של ניטור
                engine.run_analysis(runtime_sec=30)
            return True
        except Exception as e:
            print(f"[!] Regress filtering failed: {e}")
            return False

    def _is_valid_sample(self, path: Path):
        if not path.exists():
            print(f"[!] File not found: {path}")
            return False
        if path.suffix.lower() != '.py':
            print(f"[!] Invalid file type: {path.suffix}")
            return False
        return True