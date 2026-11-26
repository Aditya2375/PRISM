"""3-Node Revocation Module for Key Identity Guard.

Three Node objects in one process with in-memory transport,
revocation signing/propagation, heal sync logic.

Protocol:
- Each node has a long-term signing key (Ed25519+ML-DSA-65 hybrid)
- Revocations are signed and propagated to all nodes
- Heal: synchronized revocation list across all nodes
(no threading needed - in-process demo)
"""

import os
import time as _time
from typing import Dict, Set, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from kig.crypto_local import sig_keygen, sign, verify


def _transport_lock(node):
    """Context manager for node transport (no-op in single-threaded mode)."""
    # In single-threaded demo, just yield immediately
    return iter(node._transport.items())


class Node:
    """A node in the 3-node revocation network."""

    def __init__(self, node_id: str, long_term_sk: bytes):
        self.node_id = node_id
        self.long_term_sk = long_term_sk  # Hybrid Ed25519+ML-DSA signing private key

        # Revocation state
        self.revoked: Set[str] = set()  # Set of node IDs that are revoked
        self.revocation_seq: int = 0    # Monotonic sequence for revocations

        # In-memory transport for inter-node communication
        self._transport: Dict[str, 'Node'] = {}  # node_id -> Node

    def revoke(self, target_id: str, reason: str = "") -> Dict:
        """Revoke a node and return the revocation certificate.

        Args:
            target_id: The node ID to revoke
            reason: Optional reason for revocation

        Returns:
            Revocation certificate dict (signed and serialized)
        """
        self.revocation_seq += 1
        seq = self.revocation_seq

        # Create revocation certificate
        cert_data = f"{self.node_id}|{target_id}|{seq}|{_time.time()}|{reason}".encode()
        signature = sign(self.long_term_sk, cert_data)

        cert = {
            "revoker_id": self.node_id,
            "target_id": target_id,
            "seq": seq,
            "timestamp": _time.time(),
            "reason": reason,
            "signature": signature.hex(),
        }

        # Propagate to all known nodes (in-process)
        self._propagate_revocation(cert)

        # Update local revoked set
        self.revoked.add(target_id)

        return cert

    def _propagate_revocation(self, cert: Dict) -> None:
        """Propagate revocation certificate to all known nodes."""
        for other_id, other_node in self._transport.items():
            if other_id != self.node_id:
                other_node._receive_revocation(cert)

    def _receive_revocation(self, cert: Dict) -> None:
        """Receive a revocation certificate from another node.

        Updates revoked set if the target is not already revoked.
        No further propagation - that happens during initial revoke().
        """
        target_id = cert["target_id"]

        # Only add if not already revoked
        if target_id not in self.revoked:
            self.revoked.add(target_id)

    def heal(self) -> Set[str]:
        """Synchronize revocation state with all nodes (heal partition).

        Returns:
            The updated set of revoked node IDs
        """
        all_revoked = set(self.revoked)
        for other_id, other_node in self._transport.items():
            if other_id != self.node_id:
                all_revoked.update(other_node.revoked)

        self.revoked = all_revoked
        return self.revoked

    def heartbeat(self, target_id: str) -> None:
        """Send a heartbeat to a known node.

        In this simplified model, just acknowledges participation.
        """
        pass

    def get_revoked(self) -> Set[str]:
        """Return the set of revoked node IDs."""
        return self.revoked.copy()


class NodeNetwork:
    """Manage a network of exactly 3 nodes with revocation protocol."""

    def __init__(self):
        self.nodes: Dict[str, Node] = {}

        # Initialize 3 nodes with their own key pairs
        for i in range(3):
            sig_pk, sig_sk = sig_keygen()
            node_id = f"node{i+1}"
            self.nodes[node_id] = Node(node_id, sig_sk)

        # Set up transport connections between all 3 nodes (fully connected)
        node_ids = list(self.nodes.keys())
        for i, node_a_id in enumerate(node_ids):
            for j, node_b_id in enumerate(node_ids):
                if i != j:
                    self.nodes[node_a_id]._transport[node_b_id] = self.nodes[node_b_id]

    def revoke_node(self, revoker_id: str, target_id: str, reason: str = "") -> Optional[Dict]:
        """Revoke a node by the specified revoker.

        Args:
            revoker_id: The node ID initiating the revocation
            target_id: The node ID to revoke
            reason: Optional reason for revocation

        Returns:
            Revocation certificate dict, or None if revoker not found
        """
        if revoker_id not in self.nodes:
            return None

        cert = self.nodes[revoker_id].revoke(target_id, reason)
        return cert

    def heal_network(self) -> Set[str]:
        """Synchronize revocation state across all nodes.

        Returns:
            The unified set of revoked node IDs
        """
        all_revoked: Set[str] = set()
        for node_id, node in self.nodes.items():
            revoked = node.heal()
            all_revoked.update(revoked)
        return all_revoked

    def get_revoked(self) -> Set[str]:
        """Return the set of all revoked node IDs across the network."""
        all_revoked: Set[str] = set()
        for node in self.nodes.values():
            all_revoked.update(node.get_revoked())
        return all_revoked

    def is_revoked(self, node_id: str) -> bool:
        """Check if a node ID is revoked across the network."""
        for node in self.nodes.values():
            if node_id in node.get_revoked():
                return True
        return False

    def execute_handshake(self, initiator_id: str, responder_id: str):
        """Execute a handshake between two nodes in the network.

        For this demo, returns a simple session object.
        In a full implementation, this would use the channel handshake protocol.
        """
        if initiator_id not in self.nodes or responder_id not in self.nodes:
            return None

        # Simple session creation for demo purposes
        import hashlib
        seed = hashlib.sha256(f"{initiator_id}{responder_id}".encode()).digest()
        skey = seed[:32]
        rkey = seed[32:64]

        from kig.channel import Session
        session = Session(skey=skey, rkey=rkey)
        return session

    def __repr__(self) -> str:
        return f"NodeNetwork(nodes={list(self.nodes.keys())}, revoked={self.get_revoked()})"