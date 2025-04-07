# run_exploratory_analysis.py
# Simple script to run the exploratory analysis

import os
import sys
import subprocess

def main():
    print("Starting Exploratory Data Analysis...")
    
    # Get the directory of this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Set up paths
    exploratory_script = os.path.join(script_dir, 'exploratory_analysis.py')
    
    # Create exploratory_analysis.py if it doesn't exist
    if not os.path.exists(exploratory_script):
        print(f"Creating exploratory_analysis.py in {script_dir}...")
        with open(exploratory_script, 'w') as f:
            with open('utils/exploratory_analysis.py', 'r') as source:
                f.write(source.read())
        print("Created exploratory_analysis.py")
    
    # Run the exploratory analysis
    try:
        result = subprocess.run([sys.executable, exploratory_script], 
                              capture_output=True, text=True)
        
        print(result.stdout)
        
        if result.stderr:
            print("Errors or warnings:")
            print(result.stderr)
            
        # Check for output directory
        output_dir = os.path.join(script_dir, 'analysis_results', 'eda')
        if os.path.exists(output_dir):
            print(f"\nResults saved to: {output_dir}")
            print("\nFiles generated:")
            for file in os.listdir(output_dir):
                print(f"  - {file}")
        
    except Exception as e:
        print(f"Error running exploratory analysis: {e}")
    
    print("\nExploratory Data Analysis complete!")

if __name__ == "__main__":
    main()