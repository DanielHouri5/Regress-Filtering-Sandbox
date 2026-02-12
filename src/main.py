import argparse, sys
from pathlib import Path
from sandbox_controller import SandboxController

def main():
    """
    The main entry point for the Simple Malware Sandbox CLI.
    
    This function parses command-line arguments, initializes the sandbox controller,
    and starts the analysis process for a provided file sample.
    """
    # Initialize the argument parser to handle CLI inputs
    parser = argparse.ArgumentParser(description="Simple Malware Sandbox")
    # Define the required argument for the suspicious file path
    parser.add_argument("--sample", required=True, help="Path to the suspicious file")
    # Parse arguments from the command line
    args = parser.parse_args()

    # Initialize the SandboxController which orchestrates the entire analysis pipeline
    controller = SandboxController()

    # Resolve the absolute path of the sample and pass it to the controller
    # If the run_sample method returns False, exit with an error status code
    if not controller.run_sample(Path(args.sample).resolve()):
        sys.exit(1)

if __name__ == "__main__":
    # Execute the main function if the script is run directly
    main()
