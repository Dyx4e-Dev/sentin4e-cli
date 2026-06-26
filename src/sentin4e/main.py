import sys
from sentin4e.cli import app
from sentin4e.exceptions import Sentin4eError
from sentin4e.logger import setup_logger, get_logger

def run() -> None:
    setup_logger(debug="--debug" in sys.argv)
    log = get_logger("sentin4e")
    try:
        app()
    except Sentin4eError as e:
        log.error(f"Execution failed: {e}")
        if "--debug" in sys.argv:
            log.exception("Detailed traceback:")
        sys.exit(1)
    except Exception as e:
        log.critical(f"Unhandled system error: {e}")
        if "--debug" in sys.argv:
            log.exception("Detailed traceback:")
        sys.exit(2)

if __name__ == "__main__":
    run()
