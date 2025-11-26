import sys
import json
import subprocess
import os

# Default host output directory
HOST_OUTPUT_DIR = os.path.abspath("./results")
CONTAINER_OUTPUT_DIR = "/tmp/enumeraga_output"

# Ensure host output directory exists
os.makedirs(HOST_OUTPUT_DIR, exist_ok=True)

def run_enumeraga(flags=None, parameters=None):
    """
    Run Enumeraga inside Docker with dynamic flags and arguments.
    Automatically mounts ./results on host to /tmp/enumeraga_output in container.
    """
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{HOST_OUTPUT_DIR}:{CONTAINER_OUTPUT_DIR}",
        "enumeraga:latest"
    ]

    if flags:
        cmd.extend(flags)
    if parameters:
        cmd.extend(parameters)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            return {
                "result": result.stdout.strip(),
                "output_dir": HOST_OUTPUT_DIR
            }
        else:
            return {"error": result.stderr.strip()}
    except Exception as e:
        return {"error": str(e)}

def handle_request(request):
    method = request.get("method")
    params = request.get("params", {})

    if method == "enumeraga":
        flags = params.get("flags", [])
        parameters = params.get("parameters", [])
        return run_enumeraga(flags, parameters)
    return {"error": f"Unknown method: {method}"}

def main():
    for line in sys.stdin:
        try:
            request = json.loads(line)
            response = handle_request(request)
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()
        except Exception as e:
            error = {"error": f"Invalid request: {str(e)}"}
            sys.stdout.write(json.dumps(error) + "\n")
            sys.stdout.flush()

if __name__ == "__main__":
    main()