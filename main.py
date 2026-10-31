import argparse
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


def main():
    parser = argparse.ArgumentParser(description="CyberForge Autonomous Multi-Agent PTES Engine")
    parser.add_argument("--config", default="config.yaml", help="Path to config YAML file")
    parser.add_argument("--tier", default="recon", choices=["recon", "breach", "deep"], help="Difficulty tier")
    parser.add_argument("--cidr", help="Override target CIDR scope (e.g. 192.168.1.0/24)")
    parser.add_argument("--serve-only", action="store_true", help="Start reporting API server only")
    args = parser.parse_args()

    orchestrator = Orchestrator(config_path=args.config)

    if args.tier:
        orchestrator.config.tier = args.tier

    if args.cidr:
        orchestrator.config.scope.allowed_cidrs = [args.cidr]
        orchestrator.scope_gate.allowed_networks.clear()
        orchestrator.scope_gate.add_cidr(args.cidr)

    if args.serve_only:
        orchestrator.start_api_server()
        logger.info("Serving API only. Press Ctrl+C to terminate.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Server terminated.")
            sys.exit(0)

    # Autonomous pipeline run
    orchestrator.run_pipeline()


if __name__ == "__main__":
    main()

