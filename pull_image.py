import subprocess

def pull_docker_image():
    """
    Pull Docker image and return full image name
    """

    user_input = input("Enter Docker image (e.g., nginx or nginx:1.23): ").strip()

    if ':' in user_input:
        image_name, tag = user_input.split(':', 1)
    else:
        image_name = user_input
        tag = 'latest'

    full_image_name = f"{image_name}:{tag}"

    try:
        print(f"\nPulling Docker image: {full_image_name}\n")
        subprocess.run(
            ["docker", "pull", full_image_name],
            check=True
        )
        print("✅ Image pulled successfully")
        return full_image_name   # ✅ RETURN STRING

    except subprocess.CalledProcessError:
        print("❌ Failed to pull image")
        return None
