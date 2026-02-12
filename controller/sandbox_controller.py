from pathlib import Path
from sandbox.execution_engine import ExecutionEngine

class SandboxController:
    """
    Orchestrates the lifecycle of the malware analysis process.
    
    The controller acts as a high-level manager, responsible for validating 
    input samples and coordinating the execution engine to perform the 
    dynamic analysis.
    """
    def run_sample(self, sample_path: Path):
        """
        Executes the analysis workflow for a given file.
        
        Args:
            sample_path (Path): The absolute path to the file targeted for analysis.
            
        Returns:
            bool: True if the analysis was completed successfully, False otherwise.
        """
        # Step 1: Perform initial safety and integrity checks on the file
        if not self._is_valid_sample(sample_path):
            return False
        
        print("-"*100)
        print(f"\n[*] Analysis started for: {sample_path.name}\n")
        
        try:
            # Step 2: Use the ExecutionEngine as a context manager
            # This ensures that the Docker container is created and cleaned up automatically
            with ExecutionEngine(sample_path) as engine:
                # Step 3: Start the dynamic monitoring and execution for a fixed duration
                engine.run_analysis(runtime_sec=30)

            return True
        
        except Exception as e:
            # Catch and log any runtime errors during the infrastructure setup or execution
            print(f"[!] Analysis failed: {e}")
            return False

    def _is_valid_sample(self, path: Path):
        """
        Validates that the provided path points to a legitimate, non-empty file.
        
        Args:
            path (Path): Path to check.
            
        Returns:
            bool: True if valid, False if the file is missing, empty or not a .py file.
        """
        # 1. Verify the path exists and is actually a file
        if not path.exists() or not path.is_file():
            print(f"[!] File not found or invalid: {path}")
            return False
        # 2. Check for Python extension - The system is designed for Python source analysis
        if path.suffix.lower() != '.py':
            print(f"[!] Invalid file type: {path.suffix}. Only .py files are supported.")
            return False
        # 3. Ensure the file contains data
        if path.stat().st_size == 0:
            print(f"[!] File is empty: {path}")
            return False
        return True
    