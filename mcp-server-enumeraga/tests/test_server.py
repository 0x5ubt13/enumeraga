import pytest
from mcp_server_enumeraga.server import build_docker_infra_command, build_docker_cloud_command

def test_build_docker_infra_command_basic():
    """Test infrastructure command building with basic arguments."""
    args = {
        "target": "192.168.1.100"
    }
    cmd = build_docker_infra_command(args)
    
    # Verify essential parts of the command
    assert "docker" in cmd
    assert "run" in cmd
    assert "--rm" in cmd
    assert "--network" in cmd
    assert "host" in cmd
    assert "gagarter/enumeraga_infra:latest" in cmd
    assert "-t" in cmd
    assert "192.168.1.100" in cmd
    
    # Verify volume mount
    assert any(":/tmp/enumeraga_output" in part for part in cmd)

def test_build_docker_infra_command_full():
    """Test infrastructure command building with all arguments."""
    args = {
        "target": "example.com",
        "output_dir": "/custom/path",
        "brute": True,
        "top_ports": "1000",
        "quiet": True,
        "verbose": True
    }
    cmd = build_docker_infra_command(args)
    
    assert "example.com" in cmd
    assert "-b" in cmd
    assert "-p" in cmd
    assert "1000" in cmd
    assert "-q" in cmd
    assert "-V" in cmd
    
    # Check volume mount for custom path
    assert any("/custom/path:/tmp/enumeraga_output" in part for part in cmd)

def test_build_docker_cloud_command_aws():
    """Test cloud command building for AWS context."""
    args = {
        "provider": "aws",
        "output_dir": "/aws/out"
    }
    cmd = build_docker_cloud_command(args)
    
    assert "aws" in cmd
    assert "gagarter/enumeraga_cloud:latest" in cmd
    
    # We can't strictly check for ~/.aws mount as it depends on local file existence
    # but we can check the logic doesn't crash
    assert len(cmd) > 5

def test_build_docker_cloud_command_azure():
    """Test cloud command building for Azure context."""
    args = {
        "provider": "azure",
        "verbose": True
    }
    cmd = build_docker_cloud_command(args)
    
    assert "azure" in cmd
    assert "-V" in cmd
