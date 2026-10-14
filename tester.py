#!/usr/bin/env python3
"""Authorized Authentication Testing Tool

A safe, configurable tool for testing authentication on your own Next.js/React
applications using Playwright. Designed for authorized testing only with
strict security controls.

Usage:
    python tester.py --config config.json
    python tester.py --config config.json --password-file password.txt
    python tester.py --create-example-config
    python tester.py --create-example-password

Security Features:
- Hostname allowlist enforcement
- HTTPS required (except localhost)
- Single password per run in production mode
- Staging mode with explicit opt-in and attempt limits
- Immediate stop on security challenges
- No credential logging or storage
- Sanitized CSV reports
"""

import sys
import argparse
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.config import (
    load_config, 
    create_example_config, 
    ConfigError,
    AppConfig,
    ExecutionMode
)
from src.password_handler import create_example_password_file, PasswordFileError
from src.browser_automation import run_auth_test


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Authorized Authentication Testing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run with configuration file
  python tester.py --config config.json
  
  # Create example configuration
  python tester.py --create-example-config
  
  # Create example password file
  python tester.py --create-example-password
  
  # Override password file from command line
  python tester.py --config config.json --password-file my-passwords.txt
        """
    )
    
    parser.add_argument(
        "--config", "-c",
        default="config.json",
        help="Path to configuration JSON file (default: config.json)"
    )
    
    parser.add_argument(
        "--password-file", "-p",
        help="Override password file path from config"
    )
    
    parser.add_argument(
        "--create-example-config",
        action="store_true",
        help="Create example configuration file and exit"
    )
    
    parser.add_argument(
        "--create-example-password",
        action="store_true",
        help="Create example password file and exit"
    )
    
    parser.add_argument(
        "--example-config-name",
        default="config.example.json",
        help="Name for example config file (default: config.example.json)"
    )
    
    parser.add_argument(
        "--example-password-name",
        default="password.txt.example",
        help="Name for example password file (default: password.txt.example)"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    
    return parser.parse_args()


def main() -> int:
    """Main entry point."""
    args = parse_args()
    
    # Handle example file creation
    if args.create_example_config:
        output_path = Path(args.example_config_name)
        create_example_config(output_path)
        print(f"Example configuration created: {output_path}")
        print("Edit this file with your target URL, selectors, and credentials.")
        return 0
    
    if args.create_example_password:
        output_path = Path(args.example_password_name)
        create_example_password_file(output_path)
        print(f"Example password file created: {output_path}")
        print("Rename to 'password.txt' and add your test password.")
        return 0
    
    # Load configuration
    config_path = Path(args.config)
    try:
        config = load_config(config_path)
    except ConfigError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        print(f"Run with --create-example-config to generate a template.", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Failed to load configuration: {e}", file=sys.stderr)
        return 1
    
    # Override password file if provided
    if args.password_file:
        config.password_file = args.password_file
    
    # Print configuration summary (without secrets)
    print("=" * 60)
    print("AUTHENTICATION TEST CONFIGURATION")
    print("=" * 60)
    print(f"Target URL:           {config.target_url}")
    print(f"Allowed Hosts:        {', '.join(config.allowed_hosts)}")
    print(f"Auth Provider:        {config.auth.provider.value}")
    print(f"Username:             {config.auth.username}")
    print(f"Execution Mode:       {config.execution_mode.value}")
    print(f"Max Attempts:         {config.maximum_attempts}")
    print(f"Password File:        {config.password_file}")
    print(f"Browser:              {config.browser.browser.value} (headless={config.browser.headless})")
    print(f"Delay Before Submit:  {config.browser.delay_before_submit_seconds}s")
    print(f"Stop on Challenge:    {config.stop_on_security_challenge}")
    print(f"Report Directory:     {config.report.report_directory}")
    print("=" * 60)
    
    # Confirm for staging mode
    if config.execution_mode == ExecutionMode.STAGING:
        print("\n⚠️  STAGING MODE ENABLED")
        print(f"   This will test up to {config.maximum_attempts} passwords.")
        print("   Ensure you have explicit authorization for this testing.")
        try:
            confirm = input("   Continue? (yes/no): ").strip().lower()
            if confirm not in ("yes", "y"):
                print("Aborted.")
                return 0
        except (EOFError, KeyboardInterrupt):
            print("\nAborted.")
            return 0
    
    # Run tests
    try:
        results = run_auth_test(config)
        
        # Exit code based on results
        has_security_stop = any(
            r.classification.result.value.startswith("STOPPED_") 
            for r in results
        )
        has_errors = any(
            r.classification.result.value in ("CONFIGURATION_ERROR", "NAVIGATION_ERROR")
            for r in results
        )
        
        if has_errors:
            return 2
        elif has_security_stop:
            return 3
        else:
            return 0
            
    except PasswordFileError as e:
        print(f"Password file error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n\nInterrupted by user.")
        return 130
    except Exception as e:
        print(f"\nTest execution failed: {type(e).__name__}: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())