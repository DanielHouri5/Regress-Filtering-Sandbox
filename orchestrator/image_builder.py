import docker, yaml
from pathlib import Path

def _load_default_image_tag():
    """
    Helper function to load the global sandbox image tag from the configuration file.
    
    Returns:
        str: The image name defined in the YAML config, or 'sandbox-runtime' as a fallback.
    """
    # Locate the configuration file relative to the project structure
    cfg = Path(__file__).resolve().parent.parent / "configs" / "sandbox_settings.yaml"
    try:
        with open(cfg, "r", encoding="utf-8") as f:
            # Safely parse the YAML and navigate to the image_name key
            return yaml.safe_load(f).get("sandbox", {}).get("image_name") 
    except Exception:
        # Fallback if config is missing or malformed to ensure the system doesn't crash
        return "sandbox-runtime"

class ImageBuilder:
    """
    Handles the automated building of the Docker analysis image.
    
    This class ensures that the runtime environment is consistently built 
    according to the specifications in the Dockerfile, allowing for 
    reproducible analysis across different host machines.
    """
    def __init__(self, dockerfile_dir="sandbox/docker", tag=None):
        """
        Initializes the builder with the source directory and identification tag.
        
        Args:
            dockerfile_dir (str): Directory containing the Dockerfile.
            tag (str, optional): The name to assign to the built image.
        """
        self.dockerfile_dir = dockerfile_dir
        # Use provided tag or fetch the default from the global settings
        self.tag = tag or _load_default_image_tag()
        # Establish connection to the host's Docker engine
        self.client = docker.from_env()

    def build(self):
        """
        Triggers the Docker build process.
        
        This method compiles the image layers based on the Dockerfile instructions.
        
        Raises:
            RuntimeError: If the Docker client fails to initialize.
        """
        if not self.client: raise RuntimeError("Docker client not initialized")
        
        print(f"[*] Building Docker image from {self.dockerfile_dir} with tag {self.tag}...")
        
        # Start the build process
        # rm=True: Remove intermediate containers after a successful build to save space
        self.client.images.build(path=self.dockerfile_dir, tag=self.tag, rm=True)

        print(f"[*] Image {self.tag} built successfully\n")
