#!/usr/bin/env python3
import subprocess
import re
import matplotlib.pyplot as plt
import numpy as np
import statistics
import time
from datetime import datetime

def run_command_and_extract_time():
    """Run the command and extract the execution time."""
    try:
        # Run the command and capture output
        result = subprocess.run(['./main', 'client'], 
                              capture_output=True, 
                              text=True, 
                              timeout=30)
        
        # Look for the time pattern in stdout or stderr
        output = result.stdout + result.stderr
        
        # Check for EOF error first
        if "read server response:EOF" in output or "read server response: EOF" in output:
            return "EOF_ERROR"
        
        # Extract time using regex - matches patterns like "4.024532ms"
        time_pattern = r'Total time taken:\s*(\d+\.?\d*)(ms|μs|s)'
        match = re.search(time_pattern, output, re.IGNORECASE)
        
        if match:
            time_value = float(match.group(1))
            unit = match.group(2).lower()
            
            # Convert to milliseconds for consistency
            if unit == 'μs' or unit == 'us':
                time_value = time_value / 1000
            elif unit == 's':
                time_value = time_value * 1000
            # ms is already in the right unit
            
            return time_value
        else:
            print(f"Warning: Could not extract time from output: {output}")
            return None
            
    except subprocess.TimeoutExpired:
        print("Command timed out")
        return None
    except FileNotFoundError:
        print("Error: './main' executable not found")
        return None
    except Exception as e:
        print(f"Error running command: {e}")
        return None

def main():
    # Configuration - adjust these as needed
    DELAY_BETWEEN_RUNS = 0.05  # seconds (0 = no delay, run back-to-back)
    NUM_RUNS = 5000
    
    print(f"Running './main client' {NUM_RUNS} times...")
    if DELAY_BETWEEN_RUNS > 0:
        print(f"With {DELAY_BETWEEN_RUNS} second delay between runs")
        print(f"Total estimated time: {(NUM_RUNS * DELAY_BETWEEN_RUNS) / 60:.1f} minutes")
    print("This may take a while...\n")
    
    times = []
    failed_runs = 0
    eof_errors = 0
    
    # Run the command multiple times
    for i in range(1, NUM_RUNS + 1):
        print(f"Run {i}/{NUM_RUNS}", end=' ')
        
        execution_time = run_command_and_extract_time()
        
        if execution_time == "EOF_ERROR":
            eof_errors += 1
            failed_runs += 1
            print("- EOF ERROR")
        elif execution_time is not None:
            times.append(execution_time)
            print(f"- {execution_time:.6f}ms")
        else:
            failed_runs += 1
            print("- FAILED")
        
        # Add delay between runs if specified
        if DELAY_BETWEEN_RUNS > 0 and i < NUM_RUNS:
            time.sleep(DELAY_BETWEEN_RUNS)
    
    if not times:
        print("No successful runs! Check if './main client' works correctly.")
        return
    
    # Calculate statistics
    if times:
        mean_time = statistics.mean(times)
        median_time = statistics.median(times)
        std_dev = statistics.stdev(times) if len(times) > 1 else 0
        min_time = min(times)
        max_time = max(times)
    else:
        print("\nNo successful runs to analyze!")
        return
    
    print(f"\n{'='*50}")
    print("PERFORMANCE STATISTICS")
    print(f"{'='*50}")
    print(f"Successful runs: {len(times)}")
    print(f"Failed runs: {failed_runs}")
    print(f"  - EOF errors: {eof_errors}")
    print(f"  - Other failures: {failed_runs - eof_errors}")
    print(f"Success rate: {(len(times)/NUM_RUNS)*100:.1f}%")
    print(f"EOF error rate: {(eof_errors/NUM_RUNS)*100:.1f}%")
    
    if times:
        print(f"Mean time: {mean_time:.6f}ms")
        print(f"Median time: {median_time:.6f}ms")
        print(f"Standard deviation: {std_dev:.6f}ms")
        print(f"Min time: {min_time:.6f}ms")
        print(f"Max time: {max_time:.6f}ms")
        print(f"Fluctuation range: {max_time - min_time:.6f}ms")
        print(f"Coefficient of variation: {(std_dev/mean_time)*100:.2f}%")
    
    # Create visualizations
    fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 10))
    fig.suptitle(f'Command Performance Analysis - ./main client\n'
                f'Success: {len(times)}, EOF Errors: {eof_errors}, Other Failures: {failed_runs - eof_errors}', 
                fontsize=14, fontweight='bold')
    
    # 1. Time series plot
    run_numbers = range(1, len(times) + 1)
    ax1.plot(run_numbers, times, 'b-', alpha=0.7, linewidth=1)
    ax1.scatter(run_numbers, times, c='red', s=10, alpha=0.6)
    ax1.axhline(y=mean_time, color='green', linestyle='--', alpha=0.8, label=f'Mean: {mean_time:.3f}ms')
    ax1.fill_between(run_numbers, mean_time - std_dev, mean_time + std_dev, 
                     alpha=0.2, color='green', label=f'±1σ: {std_dev:.3f}ms')
    ax1.set_xlabel('Run Number')
    ax1.set_ylabel('Execution Time (ms)')
    ax1.set_title('Execution Time Trend')
    ax1.legend()
    ax1.grid(True, alpha=0.3)
    
    # 2. Histogram
    ax2.hist(times, bins=20, alpha=0.7, color='skyblue', edgecolor='black')
    ax2.axvline(mean_time, color='red', linestyle='--', linewidth=2, label=f'Mean: {mean_time:.3f}ms')
    ax2.axvline(median_time, color='orange', linestyle='--', linewidth=2, label=f'Median: {median_time:.3f}ms')
    ax2.set_xlabel('Execution Time (ms)')
    ax2.set_ylabel('Frequency')
    ax2.set_title('Distribution of Execution Times')
    ax2.legend()
    ax2.grid(True, alpha=0.3)
    
    # 3. Box plot
    box_plot = ax3.boxplot(times, patch_artist=True)
    box_plot['boxes'][0].set_facecolor('lightblue')
    ax3.set_ylabel('Execution Time (ms)')
    ax3.set_title('Execution Time Box Plot')
    ax3.grid(True, alpha=0.3)
    
    # Add statistics text to box plot
    stats_text = f'Q1: {np.percentile(times, 25):.3f}ms\n'
    stats_text += f'Q3: {np.percentile(times, 75):.3f}ms\n'
    stats_text += f'IQR: {np.percentile(times, 75) - np.percentile(times, 25):.3f}ms'
    ax3.text(0.02, 0.98, stats_text, transform=ax3.transAxes, 
             verticalalignment='top', bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.8))
    
    # 4. Moving average (window of 10)
    if len(times) >= 10:
        window_size = min(10, len(times))
        moving_avg = np.convolve(times, np.ones(window_size)/window_size, mode='valid')
        moving_avg_x = range(window_size, len(times) + 1)
        
        ax4.plot(run_numbers, times, 'lightblue', alpha=0.5, label='Raw times')
        ax4.plot(moving_avg_x, moving_avg, 'red', linewidth=2, label=f'Moving avg (window={window_size})')
        ax4.set_xlabel('Run Number')
        ax4.set_ylabel('Execution Time (ms)')
        ax4.set_title('Moving Average Trend')
        ax4.legend()
        ax4.grid(True, alpha=0.3)
    else:
        ax4.text(0.5, 0.5, 'Not enough data\nfor moving average', 
                transform=ax4.transAxes, ha='center', va='center', fontsize=12)
        ax4.set_title('Moving Average (N/A)')
    
    plt.tight_layout()
    
    # Save the plot
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f'performance_analysis_{timestamp}.png'
    plt.savefig(filename, dpi=300, bbox_inches='tight')
    print(f"\nGraph saved as: {filename}")
    
    # Show the plot
    plt.show()
    
    # Save raw data to CSV
    csv_filename = f'performance_data_{timestamp}.csv'
    with open(csv_filename, 'w') as f:
        f.write('Run,Status,ExecutionTime(ms)\n')
        run_idx = 0
        for i in range(1, NUM_RUNS + 1):
            if run_idx < len(times):
                # This was a successful run
                f.write(f'{i},SUCCESS,{times[run_idx]:.6f}\n')
                run_idx += 1
            else:
                # This was a failed run - we need to track what type
                f.write(f'{i},FAILED,N/A\n')
    
    print(f"Raw data saved as: {csv_filename}")
    print(f"\nNote: EOF errors ('read server response:EOF') are tracked separately from other failures.")

if __name__ == "__main__":
    main()
