#!/usr/bin/env python3
"""
Gsec Installation Script
Automated installation and setup for Gsec web security scanner
"""

import subprocess
import sys
import os
import platform
import shutil
from pathlib import Path

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_banner():
    """Print installation banner"""
    banner = f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════════╗
║                    {Colors.WHITE}GSEC INSTALLER{Colors.CYAN}                        ║
║                                                              ║
║  {Colors.YELLOW}Automated installation and setup for Gsec{Colors.CYAN}           ║
║  {Colors.YELLOW}Web Security Scanner{Colors.CYAN}                                ║
╚══════════════════════════════════════════════════════════════╝{Colors.END}
"""
    print(banner)

def print_status(message, status="INFO"):
    """Print colored status messages"""
    colors = {
        "INFO": Colors.BLUE,
        "SUCCESS": Colors.GREEN,
        "WARNING": Colors.YELLOW,
        "ERROR": Colors.RED
    }
    print(f"{colors.get(status, Colors.WHITE)}[{status}]{Colors.END} {message}")

def run_command(cmd, description="", check=True):
    """Run command with proper error handling and user feedback"""
    if description:
        print_status(f"{description}...", "INFO")
    
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=check)
        if result.returncode == 0:
            if description:
                print_status(f"{description} - Success!", "SUCCESS")
            return True, result.stdout
        else:
            if description:
                print_status(f"{description} - Failed: {result.stderr}", "ERROR")
            return False, result.stderr
    except subprocess.CalledProcessError as e:
        if description:
            print_status(f"{description} - Error: {e}", "ERROR")
        return False, str(e)
    except Exception as e:
        if description:
            print_status(f"{description} - Unexpected error: {e}", "ERROR")
        return False, str(e)

def check_command_exists(command):
    """Check if a command exists in PATH"""
    return shutil.which(command) is not None

def install_python_dependencies():
    """Install Python dependencies from requirements.txt"""
    print_status("Installing Python dependencies...", "INFO")
    
    if not os.path.exists("requirements.txt"):
        print_status("requirements.txt not found!", "ERROR")
        return False
    
    success, output = run_command(
        f"{sys.executable} -m pip install -r requirements.txt",
        "Installing Python packages"
    )
    
    if success:
        print_status("Python dependencies installed successfully!", "SUCCESS")
        return True
    else:
        print_status("Failed to install Python dependencies", "ERROR")
        return False

def install_go():
    """Install Go if not present"""
    if check_command_exists("go"):
        print_status("Go is already installed", "SUCCESS")
        return True
    
    print_status("Go not found. Installing Go...", "WARNING")
    
    system = platform.system().lower()
    if system == "linux":
        # Try different package managers
        package_managers = [
            ("apt", "sudo apt update && sudo apt install -y golang-go"),
            ("yum", "sudo yum install -y golang"),
            ("dnf", "sudo dnf install -y golang"),
            ("pacman", "sudo pacman -S go"),
            ("zypper", "sudo zypper install -y go")
        ]
        
        for pm, cmd in package_managers:
            if check_command_exists(pm):
                success, _ = run_command(cmd, f"Installing Go via {pm}")
                if success:
                    return True
        
        print_status("Could not install Go automatically. Please install Go manually.", "ERROR")
        return False
    
    elif system == "darwin":  # macOS
        if check_command_exists("brew"):
            success, _ = run_command("brew install go", "Installing Go via Homebrew")
            return success
        else:
            print_status("Homebrew not found. Please install Go manually from https://golang.org/dl/", "ERROR")
            return False
    
    else:
        print_status(f"Unsupported OS: {system}. Please install Go manually from https://golang.org/dl/", "ERROR")
        return False

def install_nuclei():
    """Install Nuclei scanner"""
    if check_command_exists("nuclei"):
        print_status("Nuclei is already installed", "SUCCESS")
        return True
    
    if not check_command_exists("go"):
        print_status("Go is required to install Nuclei. Installing Go first...", "WARNING")
        if not install_go():
            return False
    
    success, _ = run_command(
        "go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest",
        "Installing Nuclei"
    )
    
    if success:
        # Add Go bin to PATH if needed
        go_bin = os.path.expanduser("~/go/bin")
        if go_bin not in os.environ.get("PATH", ""):
            print_status("Adding Go bin to PATH...", "INFO")
            print_status(f"Please add '{go_bin}' to your PATH environment variable", "WARNING")
        
        print_status("Nuclei installed successfully!", "SUCCESS")
        return True
    else:
        print_status("Failed to install Nuclei", "ERROR")
        return False

def install_nuclei_templates():
    """Install Nuclei templates"""
    templates_dir = Path.home() / "nuclei-templates"
    
    if templates_dir.exists():
        print_status("Nuclei templates already exist. Updating...", "INFO")
        success, _ = run_command(
            f"cd {templates_dir} && git pull",
            "Updating Nuclei templates"
        )
    else:
        success, _ = run_command(
            f"git clone https://github.com/projectdiscovery/nuclei-templates.git {templates_dir}",
            "Installing Nuclei templates"
        )
    
    if success:
        print_status("Nuclei templates ready!", "SUCCESS")
        return True
    else:
        print_status("Failed to install Nuclei templates", "ERROR")
        return False

def install_jq():
    """Install jq JSON processor"""
    if check_command_exists("jq"):
        print_status("jq is already installed", "SUCCESS")
        return True
    
    system = platform.system().lower()
    
    if system == "linux":
        package_managers = [
            ("apt", "sudo apt update && sudo apt install -y jq"),
            ("yum", "sudo yum install -y jq"),
            ("dnf", "sudo dnf install -y jq"),
            ("pacman", "sudo pacman -S jq"),
            ("zypper", "sudo zypper install -y jq")
        ]
        
        for pm, cmd in package_managers:
            if check_command_exists(pm):
                success, _ = run_command(cmd, f"Installing jq via {pm}")
                if success:
                    return True
        
        print_status("Could not install jq automatically. Please install jq manually.", "ERROR")
        return False
    
    elif system == "darwin":  # macOS
        if check_command_exists("brew"):
            success, _ = run_command("brew install jq", "Installing jq via Homebrew")
            return success
        else:
            print_status("Homebrew not found. Please install jq manually.", "ERROR")
            return False
    
    else:
        print_status(f"Unsupported OS: {system}. Please install jq manually.", "ERROR")
        return False

def create_directories():
    """Create necessary directories"""
    directories = ["output", "wordlists", "tools"]
    
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print_status(f"Created directory: {directory}", "SUCCESS")

def verify_installation():
    """Verify that all components are properly installed"""
    print_status("Verifying installation...", "INFO")
    
    checks = [
        ("Python", sys.executable),
        ("Nuclei", "nuclei"),
        ("jq", "jq"),
        ("Nuclei templates", str(Path.home() / "nuclei-templates"))
    ]
    
    all_good = True
    for name, check in checks:
        if name == "Nuclei templates":
            if os.path.exists(check):
                print_status(f"✓ {name} - Found", "SUCCESS")
            else:
                print_status(f"✗ {name} - Missing", "ERROR")
                all_good = False
        else:
            if check_command_exists(check):
                print_status(f"✓ {name} - Found", "SUCCESS")
            else:
                print_status(f"✗ {name} - Missing", "ERROR")
                all_good = False
    
    return all_good

def main():
    """Main installation function"""
    print_banner()
    
    print_status("Starting Gsec installation...", "INFO")
    print_status(f"Detected OS: {platform.system()} {platform.release()}", "INFO")
    
    # Create necessary directories
    create_directories()
    
    # Install Python dependencies
    if not install_python_dependencies():
        print_status("Installation failed at Python dependencies", "ERROR")
        return False
    
    # Install external tools
    tools_installed = True
    tools_installed &= install_nuclei()
    tools_installed &= install_nuclei_templates()
    tools_installed &= install_jq()
    
    if not tools_installed:
        print_status("Some tools failed to install, but continuing...", "WARNING")
    
    # Verify installation
    if verify_installation():
        print_status("🎉 Gsec installation completed successfully!", "SUCCESS")
        print_status("You can now run: python3 gsec.py -t <target>", "INFO")
    else:
        print_status("Installation completed with some issues. Please check the errors above.", "WARNING")
    
    return True

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_status("\nInstallation cancelled by user", "WARNING")
        sys.exit(1)
    except Exception as e:
        print_status(f"Unexpected error during installation: {e}", "ERROR")
        sys.exit(1)
