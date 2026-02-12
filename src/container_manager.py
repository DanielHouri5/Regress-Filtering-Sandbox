import os
import socket
import docker
from pathlib import Path

class ContainerManager:
    def __init__(self, image_name="sandbox-runtime"):
        self.client = docker.from_env()
        self.image_name = image_name
        self.controller_id = socket.gethostname()
        self.host_path = os.environ.get("HOST_SHARED_PATH")

    def create_container(self):
        if not self.host_path:
            raise Exception("Environment variable 'HOST_SHARED_PATH' is missing.")

        volumes = {
            f"{self.host_path}/samples": {"bind": "/sandbox/shared/samples", "mode": "ro"},
            f"{self.host_path}/reports": {"bind": "/sandbox/shared/reports", "mode": "rw"}
        }
                
        return self.client.containers.create(
            image=self.image_name,
            command=["tail", "-f", "/dev/null"],
            volumes=volumes,
            network_mode=f"container:{self.controller_id}", 
            privileged=True,
            detach=True,
            tty=True,
            stdin_open=True,
            cap_add=["NET_ADMIN", "NET_RAW"],
            name="sandbox_target"
        )

    def exec_sample(self, container, sample_filename):
        path_in_container = f"/sandbox/shared/samples/{sample_filename}"
        return container.exec_run(f"python3 {path_in_container}")