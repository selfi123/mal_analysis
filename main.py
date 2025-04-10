#!/usr/bin/env python3
"""
Simple Malware Analysis Toolkit
A simplified version of a malware analysis tool
"""

import os
import sys
from analysis.malware_analyzer import MalwareAnalyzer
from rich.console import Console
from rich.prompt import Prompt

def main():
    console = Console()
    
    # Check if file path is provided
    if len(sys.argv) < 2:
        console.print("[red]Error: Please provide a file path to analyze[/red]")
        console.print("Usage: python main.py <file_path>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    
    # Initialize analyzer
    analyzer = MalwareAnalyzer()
    
    # Optional: Set VirusTotal API key
    vt_key = os.getenv('VIRUSTOTAL_API_KEY')
    if vt_key:
        analyzer.vt_api_key = vt_key
        console.print("[green]VirusTotal API key found[/green]")
    else:
        console.print("[yellow]No VirusTotal API key found. Skipping VirusTotal analysis.[/yellow]")
    
    # Analyze file
    try:
        analyzer.analyze_file(file_path)
    except Exception as e:
        console.print(f"[red]Error during analysis: {e}[/red]")
        sys.exit(1)

if __name__ == "__main__":
    main() 