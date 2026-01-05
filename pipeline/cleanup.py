#!/usr/bin/env python3
"""
AI-SSD Pipeline Cleanup Script

This script removes all generated artifacts from the AI-SSD pipeline,
allowing for a clean slate to re-run the pipeline from scratch.

Cleans:
  - Phase 1: Docker builds, results, and container images
  - Phase 2: Generated patches and summaries
  - Phase 3: Validation builds, results, and container images
  - Phase 4: Reports and visualizations
  - Logs: All log files

Author: AI-SSD Project
Date: 2026-01-04
"""

import os
import sys
import shutil
import argparse
import subprocess
from pathlib import Path
from typing import List, Tuple
from datetime import datetime

# =============================================================================
# Configuration
# =============================================================================

BASE_DIR = Path(__file__).parent.resolve()

# Directories to clean (relative to BASE_DIR)
CLEANUP_TARGETS = {
    'phase1': {
        'description': 'Phase 1: Vulnerability Reproduction',
        'directories': [
            'docker_builds',
            'results',
        ],
        'files': [],
        'docker_images': ['ai-ssd-cve-*', 'glibc-cve-*'],
    },
    'phase2': {
        'description': 'Phase 2: Patch Generation',
        'directories': [
            'patches',
        ],
        'files': [],
        'docker_images': [],
    },
    'phase3': {
        'description': 'Phase 3: Patch Validation',
        'directories': [
            'validation_builds',
            'validation_results',
        ],
        'files': [],
        'docker_images': ['validation-*', 'ai-ssd-validation-*'],
    },
    'phase4': {
        'description': 'Phase 4: Automated Reporting',
        'directories': [
            'reports',
        ],
        'files': [],
        'docker_images': [],
    },
    'logs': {
        'description': 'Log Files',
        'directories': [
            'logs',
        ],
        'files': [],
        'docker_images': [],
    },
}

# Colors for terminal output
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    MAGENTA = '\033[0;35m'
    CYAN = '\033[0;36m'
    WHITE = '\033[1;37m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

# =============================================================================
# Utility Functions
# =============================================================================

def print_header(text: str):
    """Print a formatted header."""
    print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.WHITE}  {text}{Colors.RESET}")
    print(f"{Colors.CYAN}{'='*60}{Colors.RESET}\n")

def print_section(text: str):
    """Print a section header."""
    print(f"\n{Colors.YELLOW}--- {text} ---{Colors.RESET}")

def print_success(text: str):
    """Print success message."""
    print(f"  {Colors.GREEN}✓{Colors.RESET} {text}")

def print_warning(text: str):
    """Print warning message."""
    print(f"  {Colors.YELLOW}⚠{Colors.RESET} {text}")

def print_error(text: str):
    """Print error message."""
    print(f"  {Colors.RED}✗{Colors.RESET} {text}")

def print_info(text: str):
    """Print info message."""
    print(f"  {Colors.BLUE}ℹ{Colors.RESET} {text}")

def get_directory_size(path: Path) -> int:
    """Get total size of a directory in bytes."""
    total = 0
    if path.exists() and path.is_dir():
        for entry in path.rglob('*'):
            if entry.is_file():
                try:
                    total += entry.stat().st_size
                except (OSError, PermissionError):
                    pass
    return total

def format_size(size_bytes: int) -> str:
    """Format bytes to human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"

def count_files(path: Path) -> int:
    """Count files in a directory recursively."""
    if not path.exists():
        return 0
    return sum(1 for _ in path.rglob('*') if _.is_file())

# =============================================================================
# Cleanup Functions
# =============================================================================

class PipelineCleaner:
    """Handles cleanup of pipeline artifacts."""
    
    def __init__(self, base_dir: Path, dry_run: bool = False, 
                 include_docker: bool = True, verbose: bool = False):
        self.base_dir = base_dir
        self.dry_run = dry_run
        self.include_docker = include_docker
        self.verbose = verbose
        self.stats = {
            'directories_removed': 0,
            'files_removed': 0,
            'docker_images_removed': 0,
            'space_freed': 0,
            'errors': 0,
        }
    
    def analyze(self) -> dict:
        """Analyze what would be cleaned without actually cleaning."""
        analysis = {}
        
        for target_key, target in CLEANUP_TARGETS.items():
            target_analysis = {
                'description': target['description'],
                'directories': [],
                'files': [],
                'docker_images': [],
                'total_size': 0,
                'total_files': 0,
            }
            
            # Check directories
            for dir_name in target['directories']:
                dir_path = self.base_dir / dir_name
                if dir_path.exists():
                    size = get_directory_size(dir_path)
                    file_count = count_files(dir_path)
                    target_analysis['directories'].append({
                        'path': str(dir_path),
                        'size': size,
                        'file_count': file_count,
                    })
                    target_analysis['total_size'] += size
                    target_analysis['total_files'] += file_count
            
            # Check files
            for file_pattern in target.get('files', []):
                for file_path in self.base_dir.glob(file_pattern):
                    if file_path.exists():
                        size = file_path.stat().st_size
                        target_analysis['files'].append({
                            'path': str(file_path),
                            'size': size,
                        })
                        target_analysis['total_size'] += size
                        target_analysis['total_files'] += 1
            
            # Check Docker images
            if self.include_docker:
                for pattern in target.get('docker_images', []):
                    images = self._find_docker_images(pattern)
                    target_analysis['docker_images'].extend(images)
            
            analysis[target_key] = target_analysis
        
        return analysis
    
    def _find_docker_images(self, pattern: str) -> List[dict]:
        """Find Docker images matching a pattern."""
        images = []
        try:
            # Convert glob pattern to Docker filter
            filter_pattern = pattern.replace('*', '')
            
            result = subprocess.run(
                ['docker', 'images', '--format', '{{.Repository}}:{{.Tag}}\t{{.Size}}\t{{.ID}}'],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line and filter_pattern in line:
                        parts = line.split('\t')
                        if len(parts) >= 3:
                            images.append({
                                'name': parts[0],
                                'size': parts[1],
                                'id': parts[2],
                            })
        except Exception as e:
            if self.verbose:
                print_warning(f"Could not check Docker images: {e}")
        
        return images
    
    def clean_directory(self, dir_path: Path) -> Tuple[bool, int, int]:
        """Remove a directory and its contents."""
        if not dir_path.exists():
            return True, 0, 0
        
        size = get_directory_size(dir_path)
        file_count = count_files(dir_path)
        
        if self.dry_run:
            return True, size, file_count
        
        try:
            shutil.rmtree(dir_path)
            # Recreate empty directory
            dir_path.mkdir(parents=True, exist_ok=True)
            return True, size, file_count
        except Exception as e:
            print_error(f"Failed to remove {dir_path}: {e}")
            return False, 0, 0
    
    def clean_file(self, file_path: Path) -> Tuple[bool, int]:
        """Remove a single file."""
        if not file_path.exists():
            return True, 0
        
        size = file_path.stat().st_size
        
        if self.dry_run:
            return True, size
        
        try:
            file_path.unlink()
            return True, size
        except Exception as e:
            print_error(f"Failed to remove {file_path}: {e}")
            return False, 0
    
    def clean_docker_image(self, image_id: str) -> bool:
        """Remove a Docker image."""
        if self.dry_run:
            return True
        
        try:
            result = subprocess.run(
                ['docker', 'rmi', '-f', image_id],
                capture_output=True, text=True, timeout=60
            )
            return result.returncode == 0
        except Exception as e:
            print_error(f"Failed to remove Docker image {image_id}: {e}")
            return False
    
    def clean_target(self, target_key: str) -> bool:
        """Clean a specific target category."""
        if target_key not in CLEANUP_TARGETS:
            print_error(f"Unknown target: {target_key}")
            return False
        
        target = CLEANUP_TARGETS[target_key]
        print_section(target['description'])
        
        success = True
        
        # Clean directories
        for dir_name in target['directories']:
            dir_path = self.base_dir / dir_name
            if dir_path.exists():
                ok, size, files = self.clean_directory(dir_path)
                if ok:
                    self.stats['directories_removed'] += 1
                    self.stats['files_removed'] += files
                    self.stats['space_freed'] += size
                    action = "Would remove" if self.dry_run else "Removed"
                    print_success(f"{action}: {dir_path} ({format_size(size)}, {files} files)")
                else:
                    success = False
                    self.stats['errors'] += 1
            else:
                if self.verbose:
                    print_info(f"Directory not found: {dir_path}")
        
        # Clean files
        for file_pattern in target.get('files', []):
            for file_path in self.base_dir.glob(file_pattern):
                ok, size = self.clean_file(file_path)
                if ok:
                    self.stats['files_removed'] += 1
                    self.stats['space_freed'] += size
                    action = "Would remove" if self.dry_run else "Removed"
                    print_success(f"{action}: {file_path} ({format_size(size)})")
                else:
                    success = False
                    self.stats['errors'] += 1
        
        # Clean Docker images
        if self.include_docker:
            for pattern in target.get('docker_images', []):
                images = self._find_docker_images(pattern)
                for img in images:
                    if self.clean_docker_image(img['id']):
                        self.stats['docker_images_removed'] += 1
                        action = "Would remove" if self.dry_run else "Removed"
                        print_success(f"{action} Docker image: {img['name']} ({img['size']})")
                    else:
                        success = False
                        self.stats['errors'] += 1
        
        return success
    
    def clean_all(self, targets: List[str] = None) -> bool:
        """Clean all or specified targets."""
        if targets is None:
            targets = list(CLEANUP_TARGETS.keys())
        
        success = True
        for target in targets:
            if not self.clean_target(target):
                success = False
        
        return success
    
    def print_summary(self):
        """Print cleanup summary."""
        print_section("Cleanup Summary")
        
        action = "Would be" if self.dry_run else "Were"
        
        print(f"\n  {Colors.BOLD}Statistics:{Colors.RESET}")
        print(f"    • Directories cleaned: {self.stats['directories_removed']}")
        print(f"    • Files removed: {self.stats['files_removed']}")
        print(f"    • Docker images removed: {self.stats['docker_images_removed']}")
        print(f"    • Space freed: {format_size(self.stats['space_freed'])}")
        
        if self.stats['errors'] > 0:
            print(f"    • {Colors.RED}Errors: {self.stats['errors']}{Colors.RESET}")
        
        if self.dry_run:
            print(f"\n  {Colors.YELLOW}This was a dry run. No files were actually deleted.{Colors.RESET}")
            print(f"  {Colors.YELLOW}Run without --dry-run to perform actual cleanup.{Colors.RESET}")

# =============================================================================
# Interactive Mode
# =============================================================================

def interactive_cleanup(cleaner: PipelineCleaner):
    """Run cleanup in interactive mode with user confirmation."""
    print_header("AI-SSD Pipeline Cleanup - Interactive Mode")
    
    # Analyze current state
    print_info("Analyzing pipeline artifacts...")
    analysis = cleaner.analyze()
    
    # Display what would be cleaned
    total_size = 0
    total_files = 0
    total_images = 0
    
    for target_key, data in analysis.items():
        if data['total_size'] > 0 or data['docker_images']:
            print(f"\n  {Colors.BOLD}{data['description']}:{Colors.RESET}")
            
            for dir_info in data['directories']:
                print(f"    📁 {dir_info['path']}")
                print(f"       {dir_info['file_count']} files, {format_size(dir_info['size'])}")
            
            for img in data['docker_images']:
                print(f"    🐳 {img['name']} ({img['size']})")
            
            total_size += data['total_size']
            total_files += data['total_files']
            total_images += len(data['docker_images'])
    
    if total_size == 0 and total_images == 0:
        print_info("No artifacts found to clean. Pipeline is already clean.")
        return
    
    print(f"\n  {Colors.BOLD}Total:{Colors.RESET}")
    print(f"    • Files: {total_files}")
    print(f"    • Size: {format_size(total_size)}")
    print(f"    • Docker Images: {total_images}")
    
    # Confirm
    print(f"\n{Colors.YELLOW}This will permanently delete the above files and directories.{Colors.RESET}")
    response = input(f"\n{Colors.BOLD}Proceed with cleanup? [y/N]: {Colors.RESET}").strip().lower()
    
    if response == 'y':
        print()
        cleaner.dry_run = False
        cleaner.clean_all()
        cleaner.print_summary()
    else:
        print_info("Cleanup cancelled.")

# =============================================================================
# CLI Entry Point
# =============================================================================

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="AI-SSD Pipeline Cleanup Script",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Targets:
  phase1    - Docker builds, results (Phase 1: Vulnerability Reproduction)
  phase2    - Generated patches (Phase 2: Patch Generation)
  phase3    - Validation builds and results (Phase 3: Patch Validation)
  phase4    - Reports and charts (Phase 4: Automated Reporting)
  logs      - All log files
  all       - Everything (default)

Examples:
  # Show what would be cleaned (dry run)
  python cleanup.py --dry-run
  
  # Interactive mode with confirmation
  python cleanup.py --interactive
  
  # Clean everything without confirmation
  python cleanup.py --force
  
  # Clean only specific phases
  python cleanup.py --targets phase2 phase3
  
  # Clean without removing Docker images
  python cleanup.py --no-docker
        """
    )
    
    parser.add_argument(
        '--base-dir',
        type=str,
        default=str(BASE_DIR),
        help='Base directory for the project (default: script directory)'
    )
    
    parser.add_argument(
        '--targets',
        type=str,
        nargs='+',
        choices=['phase1', 'phase2', 'phase3', 'phase4', 'logs', 'all'],
        default=['all'],
        help='Specific targets to clean (default: all)'
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be deleted without actually deleting'
    )
    
    parser.add_argument(
        '--force', '-f',
        action='store_true',
        help='Skip confirmation prompt'
    )
    
    parser.add_argument(
        '--interactive', '-i',
        action='store_true',
        help='Interactive mode with detailed preview and confirmation'
    )
    
    parser.add_argument(
        '--no-docker',
        action='store_true',
        help='Do not remove Docker images'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    return parser.parse_args()


def main():
    """Main entry point."""
    args = parse_arguments()
    
    base_dir = Path(args.base_dir)
    
    if not base_dir.exists():
        print_error(f"Base directory not found: {base_dir}")
        return 1
    
    # Determine targets
    if 'all' in args.targets:
        targets = list(CLEANUP_TARGETS.keys())
    else:
        targets = args.targets
    
    # Create cleaner
    cleaner = PipelineCleaner(
        base_dir=base_dir,
        dry_run=args.dry_run,
        include_docker=not args.no_docker,
        verbose=args.verbose
    )
    
    # Run cleanup
    if args.interactive:
        interactive_cleanup(cleaner)
    else:
        print_header("AI-SSD Pipeline Cleanup")
        
        if args.dry_run:
            print_warning("DRY RUN MODE - No files will be deleted\n")
        
        if not args.force and not args.dry_run:
            print(f"{Colors.YELLOW}This will delete all generated pipeline artifacts.{Colors.RESET}")
            response = input(f"{Colors.BOLD}Continue? [y/N]: {Colors.RESET}").strip().lower()
            if response != 'y':
                print_info("Cleanup cancelled.")
                return 0
            print()
        
        success = cleaner.clean_all(targets)
        cleaner.print_summary()
        
        return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
