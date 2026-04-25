import copy

import uvicorn
from uvicorn.config import LOGGING_CONFIG

from .config import load_settings


def main() -> None:
    settings = load_settings()

    log_config = copy.deepcopy(LOGGING_CONFIG)
    log_config["handlers"]["file"] = {
        "class": "logging.FileHandler",
        "filename": "sanitizer.log",
        "formatter": "default",
    }
    log_config["loggers"]["piiproxy"] = {
        "handlers": ["file"],
        "level": "INFO",
        "propagate": False,
    }

    uvicorn.run(
        "piiproxy.server:app",
        host=settings.server.host,
        port=settings.server.port,
        log_level="info",
        log_config=log_config,
    )


if __name__ == "__main__":
    main()
