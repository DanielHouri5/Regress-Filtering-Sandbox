import docker
from pathlib import Path
from .image_builder import ImageBuilder

class ContainerManager:
    """
    Manages the lifecycle and configuration of Docker containers for the sandbox.
    
    This class handles environment preparation, image verification, volume mapping,
    and the secure execution of samples using system-level tracing.
    """
    def __init__(self, image_name="sandbox-runtime"):
        """
        Initializes the Docker client and prepares the host environment paths.
        
        Args:
            image_name (str): The tag of the Docker image to use for the sandbox.
        """
        # Connect to the local Docker daemon using environment variables
        self.client = docker.from_env()
        self.image_name = image_name
        # Resolve the absolute path of the project root to ensure correct volume binding
        self.host_root = Path('.').resolve()
        # Verify that the required analysis image is ready for use
        self._ensure_image_exists()

    def _ensure_image_exists(self):
        """
        Checks for the existence of the sandbox image. 
        If missing, it triggers the automated build process.
        """
        try:
            self.client.images.get(self.image_name)
        except docker.errors.ImageNotFound:
            print(f"[!] Image '{self.image_name}' not found locally.")
            # Instantiate the ImageBuilder to create the environment from the Dockerfile
            builder = ImageBuilder(tag=self.image_name)
            builder.build()

    def create_container(self):
        """
        Configures and creates a restricted Docker container for analysis.
        
        Returns:
            docker.models.containers.Container: The created (but not yet started) container object.
        """
        # Define volume mappings between the Host and the Guest (Container)
        # Samples are Read-Only (ro) for safety; Reports are Read-Write (rw) for logging
        volumes = {
            str(self.host_root / "shared" / "samples"): {"bind": "/samples", "mode": "ro"},
            str(self.host_root / "shared" / "reports"): {"bind": "/reports", "mode": "rw"}
        }

        # Security and Resource Constraints:
        # - mem_limit: Prevents 'Memory Bomb' malware from crashing the host
        # - network_disabled: Can be toggled to isolate or monitor network traffic
        # - cap_add: SYS_PTRACE is required to allow strace to hook into processes
        return self.client.containers.create(
            image=self.image_name,
            command=["sleep", "infinity"], # Keep the container alive for the monitor
            volumes=volumes,
            network_disabled=False, 
            mem_limit="256m",
            detach=True,
            cap_add=["SYS_PTRACE"] 
        )

    def exec_sample(self, container, sample_filename):
        """
        Executes the malware sample inside the container wrapped in a system call tracer.
        
        Args:
            container: The active Docker container instance.
            sample_filename (str): The name of the Python file to analyze.
            
        Returns:
            ExecResult: The result of the execution command.
        """
        # Filter strace to capture only relevant categories of system calls
        trace_filters = "process,network,file,desc"

        # Command Construction:
        # -f: Follow child processes (forks)
        # -tt: Include microsecond-precision timestamps
        # -o: Redirect raw trace output to the shared report volume
        cmd = [
            "sh", "-c",
            f"strace -f -tt -e trace={trace_filters} -o /reports/trace.log python /samples/{sample_filename}"
        ]
        # Execute the command in detached mode so the Python monitor can run concurrently
        return container.exec_run(cmd, detach=True)
