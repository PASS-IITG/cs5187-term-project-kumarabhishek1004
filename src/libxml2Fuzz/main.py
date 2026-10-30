"""Command line entry point for the interconnected LLM-driven libxml2 bug-finding system."""
import argparse
import sys
from pathlib import Path

from src.core.appConfig import AppConfig
from src.core.appLogger import getLogger, setupLogging

defaultConfigPath = Path(__file__).resolve().parent / "config" / "settings.json"


def buildArgumentParser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Interconnected LLM-driven 3-engine fuzzing for libxml2")
    parser.add_argument("--config", default=str(defaultConfigPath), help="path to settings.json")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("check", help="verify toolchain and LLM provider configuration")
    subparsers.add_parser("llmtest", help="send one tiny request to every configured LLM provider (validates keys and model IDs)")
    setupParser = subparsers.add_parser("setup", help="clone libxml2 and build all sanitizer/coverage variants")
    setupParser.add_argument("--update", action="store_true", help="pull latest upstream master first")
    baselineParser = subparsers.add_parser("baseline", help="start upstream harnesses in the background (run on day 1)")
    baselineParser.add_argument("--hours", type=float, default=24.0)
    subparsers.add_parser("discover", help="create hypotheses from the 4 sources")
    subparsers.add_parser("audit", help="Engine 1: audit pending hypotheses")
    subparsers.add_parser("harness", help="Engine 3: generate harnesses for API gaps")
    subparsers.add_parser("differential", help="Engine 2: differential/metamorphic testing")
    fuzzParser = subparsers.add_parser("fuzz", help="long fuzzing campaign over all validated harnesses")
    fuzzParser.add_argument("--hours", type=float, default=4.0)
    allParser = subparsers.add_parser("all", help="run the complete interconnected pipeline")
    allParser.add_argument("--hours", type=float, default=4.0, help="fuzzing hours per cycle")
    allParser.add_argument("--cycles", type=int, default=2)
    subparsers.add_parser("status", help="print hypotheses, findings and LLM usage")
    subparsers.add_parser("addReference", help="install the hand-written DOM-mutation harness (uses no LLM tokens)")
    subparsers.add_parser("retryFailed", help="re-queue hypotheses that failed only because LLM quota/limits ran out")
    return parser


def main() -> int:
    arguments = buildArgumentParser().parse_args()
    config = AppConfig(arguments.config)
    setupLogging(config.getPath("paths.logDir"), config.get("logging.consoleLevel", "INFO"))
    logger = getLogger("main")
    logger.info("Command: %s | logs in %s", arguments.command, config.getPath("paths.logDir"))
    for startupNote in config.startupNotes:
        logger.info(startupNote)
    unsafePathProblems = config.findUnsafePathProblems()
    if unsafePathProblems and arguments.command not in ("check", "llmtest", "status"):
        for problem in unsafePathProblems:
            logger.error("UNSAFE PATH: %s", problem)
        logger.error("libFuzzer's -fork mode runs child jobs through the shell WITHOUT quoting paths, so every fuzz job would fail. "
                     "Move the project to a plain path (letters, digits, _ - . / only), e.g. ~/fuzzProject, delete work/builds and "
                     "work/baseline, then run 'python main.py setup' again.")
        return 2
    from src.orchestrator import Orchestrator
    orchestrator = Orchestrator(config)
    try:
        if arguments.command == "check":
            orchestrator.builder.checkToolchain()
        elif arguments.command == "llmtest":
            return 0 if orchestrator.runLlmSelfTest() else 1
        elif arguments.command == "setup":
            return 0 if orchestrator.runSetup(arguments.update) else 1
        elif arguments.command == "baseline":
            orchestrator.runBaseline(arguments.hours)
            logger.info("Baseline running. Press Ctrl+C to stop early; corpora are kept in work/baseline/corpus.")
            orchestrator.baseline.waitForCompletion()
        elif arguments.command == "discover":
            orchestrator.runDiscovery()
        elif arguments.command == "audit":
            orchestrator.runAuditLoop()
        elif arguments.command == "harness":
            orchestrator.runHarnessGeneration()
        elif arguments.command == "differential":
            orchestrator.runDifferentialTesting()
        elif arguments.command == "fuzz":
            orchestrator.runFuzzCampaign(arguments.hours)
        elif arguments.command == "all":
            orchestrator.runAll(arguments.hours, arguments.cycles)
        elif arguments.command == "status":
            orchestrator.printStatus()
        elif arguments.command == "addReference":
            orchestrator.installReferenceHarness()
        elif arguments.command == "retryFailed":
            orchestrator.retryFailedHypotheses()
    except KeyboardInterrupt:
        logger.warning("Interrupted by user; stopping background fuzzers")
        orchestrator.baseline.stopBackgroundFuzzing()
        return 130
    except Exception:
        logger.exception("UNHANDLED ERROR - see traceback above")
        orchestrator.baseline.stopBackgroundFuzzing()
        return 1
    if arguments.command not in ("status", "check", "llmtest", "addReference"):
        orchestrator.router.logUsageSummary()
    return 0


if __name__ == "__main__":
    sys.exit(main())
