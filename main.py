#!/usr/bin/env python3
"""
Simple Malware Analysis Toolkit
A simplified version of a malware analysis tool
"""

import os
import sys
from analysis.malware_analyzer import MalwareAnalyzer
from rich.console import Console

def main():
    console = Console()
    
    # Check if a path is provided
    if len(sys.argv) < 2:
        console.print("[red]Error: Please provide a file or folder path to analyze[/red]")
        console.print("Usage: python main.py <path>")
        sys.exit(1)
    
    path = sys.argv[1]
    
    # Check if the path exists
    if not os.path.exists(path):
        console.print("[red]Error: Path does not exist[/red]")
        sys.exit(1)
    
    # Initialize analyzer
    analyzer = MalwareAnalyzer()
    
    # Optional: Set VirusTotal API key
    vt_key = os.getenv('VIRUSTOTAL_API_KEY')
    if vt_key:
        analyzer.vt_api_key = vt_key
        console.print("[green]VirusTotal API key found[/green]")
    else:
        console.print("[yellow]No VirusTotal API key found. Skipping VirusTotal analysis.[/yellow]")
    
    # Analyze file or folder
    if os.path.isfile(path):
        console.print(f"[cyan]Analyzing file: {path}[/cyan]")
        try:
            analyzer.analyze_file(path)
        except Exception as e:
            console.print(f"[red]Error analyzing {path}: {e}[/red]")
            sys.exit(1)
    elif os.path.isdir(path):
        console.print(f"[cyan]Analyzing folder: {path}[/cyan]")
        for root, dirs, files in os.walk(path):
            for file in files:
                file_full_path = os.path.join(root, file)
                console.print(f"[cyan]Analyzing file: {file_full_path}[/cyan]")
                try:
                    analyzer.analyze_file(file_full_path)
                except Exception as e:
                    console.print(f"[yellow]Warning: Could not analyze {file_full_path}: {e}[/yellow]")
    else:
        console.print("[red]Error: Provided path is neither a file nor a directory[/red]")
        sys.exit(1)

if __name__ == "__main__":
    main()