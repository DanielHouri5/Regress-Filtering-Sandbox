import argparse, sys
from pathlib import Path
from sandbox_controller import SandboxController

def main():
    parser = argparse.ArgumentParser(description="Simple Malware Sandbox")
    parser.add_argument("--sample", required=True, help="Path to the suspicious file")
    args = parser.parse_args()

    controller = SandboxController()
    if not controller.run_sample(Path(args.sample).resolve()):
        sys.exit(1)

if __name__ == "__main__":
    main()
