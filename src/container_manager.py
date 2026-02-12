import docker
from pathlib import Path

class ContainerManager:
    def __init__(self, image_name="sandbox-runtime"):
        self.client = docker.from_env()
        self.image_name = image_name
        self.host_root = Path('.').resolve()
        
        self._ensure_image_exists()

    def _ensure_image_exists(self):
        try:
            self.client.images.get(self.image_name)
        except docker.errors.ImageNotFound:
            print(f"[*] Image '{self.image_name}' not found. Building environment (this may take a minute)...")
            
            self.client.images.build(
                path=".", 
                tag=self.image_name, 
                rm=True  
            )
            print(f"[+] Image '{self.image_name}' built successfully with iptables and scapy.")

    def create_container(self):
        volumes = {
            str(self.host_root / "shared" / "samples"): {"bind": "/samples", "mode": "ro"},
            str(self.host_root / "shared" / "reports"): {"bind": "/reports", "mode": "rw"}
        }
        
        return self.client.containers.create(
            image=self.image_name,
            command=["sleep", "infinity"], 
            volumes=volumes,
            network_mode="host",   
            privileged=True,      
            detach=True,
            cap_add=["NET_ADMIN", "NET_RAW"] 
        )

    def exec_sample(self, container, sample_filename):
        return container.exec_run(f"python3 /samples/{sample_filename}", detach=True)