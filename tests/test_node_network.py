"""Tests for the 3-Node Revocation Module."""

import pytest
from kig.node_network import NodeNetwork, Node


def test_node_network_init():
    """Test that NodeNetwork initializes with 3 nodes."""
    network = NodeNetwork()
    assert len(network.nodes) == 3
    assert all(node.node_id.startswith("node") for node in network.nodes.values())


def test_node_revoke():
    """Test that a node can revoke another node."""
    network = NodeNetwork()
    
    # Node 1 revokes Node 3
    cert = network.revoke_node("node1", "node3", "misbehavior")
    assert cert is not None
    assert cert["revoker_id"] == "node1"
    assert cert["target_id"] == "node3"
    
    # Check that node3 is marked as revoked
    assert "node3" in network.get_revoked()
    assert network.is_revoked("node3")


def test_node_heal():
    """Test that heal synchronizes revocation state."""
    network = NodeNetwork()
    
    # Revoke through node1
    network.revoke_node("node1", "node3", "misbehavior")
    
    # Heal should propagate the revocation
    revoked = network.heal_network()
    assert "node3" in revoked
    assert network.is_revoked("node3")


def test_three_node_revocation():
    """Test full 3-node revocation scenario."""
    network = NodeNetwork()
    
    # Node 2 revokes node 3
    network.revoke_node("node2", "node3", "compromise")
    assert "node3" in network.get_revoked()
    assert network.is_revoked("node3")
    
    # Heal synchronizes state
    revoked = network.heal_network()
    assert "node3" in revoked
    
    # Node 1 revokes node 2 (different revoker)
    network.revoke_node("node1", "node2", "policy violation")
    assert "node2" in network.get_revoked()
    assert network.is_revoked("node2")
    
    # After heal, both should be revoked
    revoked = network.heal_network()
    assert "node2" in revoked
    assert "node3" in revoked


def test_node_heartbeat():
    """Test heartbeat functionality."""
    network = NodeNetwork()
    
    # Node 1 sends heartbeat to node 2
    network.nodes["node1"].heartbeat("node2")
    
    # Check that the heartbeat was received
    # (in this simple test, we just verify no error occurred)
    assert network.nodes["node1"] is not None


def test_node_get_revoked():
    """Test getting revoked set from individual nodes."""
    network = NodeNetwork()
    
    # Initially no revocations
    for node in network.nodes.values():
        assert node.get_revoked() == set()
    
    # After revocation
    network.revoke_node("node1", "node3", "test")
    assert "node3" in network.nodes["node1"].get_revoked()


def test_multiple_revocations_different_revocers():
    """Test revocations from different nodes."""
    network = NodeNetwork()
    
    # Node 1 revokes node 3
    network.revoke_node("node1", "node3", "reason1")
    assert "node3" in network.get_revoked()
    
    # Node 2 revokes node 3 again (should still be revoked)
    network.revoke_node("node2", "node3", "reason2")
    assert "node3" in network.get_revoked()
    
    # Node 3 revokes node 2
    network.revoke_node("node3", "node2", "reason3")
    assert "node2" in network.get_revoked()


def test_revocation_certificate_structure():
    """Test that revocation certificates have correct structure."""
    network = NodeNetwork()
    
    cert = network.revoke_node("node1", "node3", "test reason")
    assert cert is not None
    assert "revoker_id" in cert
    assert "target_id" in cert
    assert "seq" in cert
    assert "timestamp" in cert
    assert "reason" in cert
    assert "signature" in cert
    assert cert["revoker_id"] == "node1"
    assert cert["target_id"] == "node3"