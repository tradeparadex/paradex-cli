import os
from typing import Optional
from starknet_py.net.full_node_client import FullNodeClient

class EnvConfig:
    def __init__(self, env_name: str) -> None:
        self.env = env_name.lower()
        self._client: Optional[FullNodeClient] = None
        self.account_address = self.get("ACCOUNT_ADDRESS")
        self.account_private_key = self.get("ACCOUNT_PRIVATE_KEY", "0x0")

    def __str__(self) -> str:
        return f"EnvConfig(env='{self.env}', account_address='{self.account_address}')"

    def __repr__(self) -> str:
        return f"EnvConfig(env='{self.env}')"

    def get(self, key: str, default=None) -> Optional[str]:
        return os.environ.get(f"{self.env.upper()}_{key}", default)

    @property
    def client(self) -> FullNodeClient:
        if self._client is None:
            full_node_url = self.get("PSN_FULL_NODE_URL")
            if not full_node_url:
                raise ValueError(f"No PSN_FULL_NODE_URL configured for environment {self.env}")
            self._client = FullNodeClient(node_url=full_node_url)
        return self._client

# Only keep testnet and prod environments
testnet = EnvConfig("testnet")
prod = EnvConfig("prod")

# Environment mapping
env2config = {
    "testnet": testnet,
    "prod": prod,
}
