# run_data_processing.py
import subprocess
import logging
import sys
import time
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('data_processing.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def run_script(script_path):
    """Run a Python script and log the results."""
    script_name = os.path.basename(script_path)
    logger.info(f"Running {script_name}...")
    
    try:
        result = subprocess.run(['python', script_path], 
                              check=True, 
                              capture_output=True, 
                              text=True)
        logger.info(f"{script_name} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Error running {script_name}: {e}")
        logger.error(f"Error output: {e.stderr}")
        return False

def main():
    """Main function to run all data processing steps."""
    start_time = time.time()
    logger.info("Starting all data processing steps...")
    
    # Get the directory where this script is located
    utils_dir = os.path.dirname(os.path.abspath(__file__))
    
    # List of scripts to run in order (relative to utils directory)
    script_names = [
        "data_quality_enhancement.py",
        "data_standardization.py",
        "vulnerability_attribution.py",
        "optimize_database.py"
    ]
    
    # Create full paths to each script
    scripts = [os.path.join(utils_dir, script) for script in script_names]
    
    success_count = 0
    for script in scripts:
        if run_script(script):
            success_count += 1
    
    end_time = time.time()
    elapsed_time = end_time - start_time
    
    logger.info(f"All data processing steps completed. "
               f"{success_count}/{len(scripts)} scripts ran successfully. "
               f"Total time: {elapsed_time:.2f} seconds")

if __name__ == "__main__":
    main()