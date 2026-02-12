import docker
from pathlib import Path

class ContainerManager:
    def __init__(self, image_name="sandbox-runtime"):
        self.client = docker.from_env()
        self.image_name = image_name
        self.host_root = Path('.').resolve()

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
            detach=True
        )

    def exec_sample(self, container, sample_filename):
        return container.exec_run(f"python3 /samples/{sample_filename}", detach=True)
    