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
    cmd, extra_env = build_docker_cloud_command(args)

    assert "aws" in cmd
    assert "gagarter/enumeraga_cloud:latest" in cmd
    assert extra_env == {}

    # We can't strictly check for ~/.aws mount as it depends on local file existence
    # but we can check the logic doesn't crash
    assert len(cmd) > 5

def test_build_docker_cloud_command_azure():
    """Test cloud command building for Azure context."""
    args = {
        "provider": "azure",
        "verbose": True
    }
    cmd, extra_env = build_docker_cloud_command(args)

    assert "azure" in cmd
    assert "-V" in cmd
    assert extra_env == {}

def test_build_docker_cloud_command_azure_service_principal():
    """Azure service principal credentials are forwarded via the environment.

    The tenant and client IDs are passed as -e VAR=value, but the client secret is
    passed by name only (-e AZURE_CLIENT_SECRET) with its value carried in extra_env,
    so it never appears in the command-line arguments.
    """
    args = {
        "provider": "azure",
        "tenant": "11111111-1111-1111-1111-111111111111",
        "client_id": "00000000-0000-0000-0000-000000000000",
        "client_secret": "super-secret-value",
        "subscription": "22222222-2222-2222-2222-222222222222",
    }
    cmd, extra_env = build_docker_cloud_command(args)
    joined = " ".join(cmd)

    assert "AZURE_TENANT_ID=11111111-1111-1111-1111-111111111111" in joined
    assert "AZURE_CLIENT_ID=00000000-0000-0000-0000-000000000000" in joined
    assert "AZURE_SUBSCRIPTION_ID=22222222-2222-2222-2222-222222222222" in joined
    # The secret is passed by name only and never as a value on the command line.
    assert "AZURE_CLIENT_SECRET" in cmd
    assert "super-secret-value" not in joined
    assert extra_env == {"AZURE_CLIENT_SECRET": "super-secret-value"}
