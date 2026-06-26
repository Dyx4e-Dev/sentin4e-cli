import logging
from rich.logging import RichHandler

def setup_logger(debug: bool = False) -> None:
    """Configures the standard Python logger to use RichHandler."""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, show_time=False, show_path=debug)]
    )
    
    # Silence third-party loggers if not in debug mode
    if not debug:
        logging.getLogger("urllib3").setLevel(logging.WARNING)

def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
