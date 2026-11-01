import argparse
import ipaddress
import logging
import sys
import time
from cyberforge.core.orchestrator import Orchestrator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("Main")

LARGE_SCOPE_THRESHOLD = 50


def print_scope_summary(cidrs: list) -> None:
    """
    Prints a human-readable summary of the configured scope before scanning begins.
    If any CIDR covers more than LARGE_SCOPE_THRESHOLD addresses, a confirmation
    prompt is displayed so the operator can catch a wrong range early.
    """
    print()
    print("=" * 62)
    print("  CyberForge -- Pre-Scan Scope Summary")
    print("=" * 62)

    total_addresses = 0
    large_ranges = []

    for cidr in cidrs:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            count = net.num_addresses
            if net.prefixlen >= 31:
                usable = count
            else:
                usable = count - 2

            total_addresses += usable
            status = "[OK]  " if usable <= LARGE_SCOPE_THRESHOLD else "[WARN]"
            print(f"  {status}  {cidr:<20}  ->  {usable:>5} usable host address(es)")

            if usable > LARGE_SCOPE_THRESHOLD:
                large_ranges.append((cidr, usable))
        except ValueError as exc:
            print(f"  [ERROR] {cidr:<20}  ->  INVALID ({exc})")

    print("-" * 62)
    print(f"  Total usable addresses in scope: {total_addresses}")
    print("=" * 62)

    if large_ranges:
        print()
        print("  [!] LARGE SCOPE NOTICE:")
        for cidr, usable in large_ranges:
            print(
                f"  '{cidr}' covers {usable} addresses -- please confirm this\n"
                f"  matches the range given by the event organizers before proceeding."
            )
        print()


def main():
    parser = argparse.ArgumentParser(description="CyberForge Autonomous Multi-Agent PTES Engine")
    parser.add_argument("--config", default="config.json", help="Path to config file (JSON or YAML)")
    parser.add_argument("--tier", default="recon", choices=["recon", "breach", "deep"], help="Difficulty tier")
    parser.add_argument("--cidr", help="Override target CIDR scope (e.g. 192.168.1.0/24)")
    parser.add_argument("--serve-only", action="store_true", help="Start reporting API server only")
    parser.add_argument("--no-wait", action="store_true", help="Exit immediately after pipeline completes without keeping server open")
    args = parser.parse_args()

    orchestrator = Orchestrator(config_path=args.config)

    if args.tier:
        orchestrator.config.tier = args.tier

    if args.cidr:
        orchestrator.config.scope.allowed_cidrs = [args.cidr]
        orchestrator.scope_gate.allowed_networks.clear()
        orchestrator.scope_gate.add_cidr(args.cidr)

    # Always print scope summary so the operator can verify the range before anything runs
    print_scope_summary(orchestrator.config.scope.allowed_cidrs)

    if args.serve_only:
        orchestrator.load_latest_report()
        orchestrator.start_api_server()
        logger.info("Serving API and Dashboard on http://localhost:8000 with latest findings. Press Ctrl+C to terminate.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Server terminated.")
            sys.exit(0)

    # Autonomous pipeline run
    orchestrator.run_pipeline()

    if not args.no_wait:
        # Keep dashboard server running so user and judges can inspect findings
        logger.info("=" * 60)
        logger.info("Assessment Complete! Live Dashboard is available at:")
        logger.info(f"-> http://localhost:{orchestrator.config.reporting.api_port}/")
        logger.info("Press Ctrl+C to exit.")
        logger.info("=" * 60)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("CyberForge engine stopped.")


if __name__ == "__main__":
    main()

