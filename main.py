"""iOS Crackability Analyzer — application entry point.

GUI:   python main.py
CLI:   python main.py --cli path/to/app.ipa [--html out.html] [--json out.json]
"""
from __future__ import annotations

import logging
import sys

from app.logging_setup import setup_logging

log = logging.getLogger("ios_crack_analyzer")


def _install_gui_excepthook(app) -> None:
    """Log unhandled exceptions and show a dialog instead of dying silently."""
    from PySide6.QtWidgets import QMessageBox

    def hook(exc_type, exc, tb):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc, tb)
            return
        log.critical("Unhandled exception", exc_info=(exc_type, exc, tb))
        try:
            QMessageBox.critical(
                None, "Unexpected error",
                f"{exc_type.__name__}: {exc}\n\nDetails were written to the log file.",
            )
        except Exception:
            pass

    sys.excepthook = hook


def _run_gui(initial_path: str | None) -> int:
    from PySide6.QtWidgets import QApplication

    from app import __app_name__
    from app.gui.icon import make_app_icon
    from app.gui.main_window import MainWindow
    from app.gui.theme import build_stylesheet

    app = QApplication(sys.argv)
    app.setApplicationName(__app_name__)
    app.setApplicationDisplayName(__app_name__)
    app.setOrganizationName("SecurityTools")
    app.setStyleSheet(build_stylesheet())
    app.setWindowIcon(make_app_icon())
    _install_gui_excepthook(app)

    win = MainWindow()
    win.show()
    if initial_path:
        win.start_analysis(initial_path)
    return app.exec()


def main() -> int:
    setup_logging()
    argv = sys.argv[1:]
    if argv and argv[0] == "--cli":
        from app.cli import run
        return run(argv[1:])
    if argv and argv[0] == "--device-op":
        # headless device op for the desktop UI; results go to a file (no stdout)
        from app.device_ops import main as device_main
        return device_main(argv[1:])
    if argv and argv[0] == "--frida-selftest":
        # diagnostic: fetch + load a specific Frida host version (no device needed).
        # A windowed build has sys.stdout is None, so seed the streams (else the
        # print() below would itself crash) and also log the outcome — the log
        # file is the only observable channel in a no-console exe.
        from app.cli import _ensure_streams
        _ensure_streams()
        from app.device import frida_manager
        want = argv[1] if len(argv) > 1 else "16.1.4"
        try:
            mod = frida_manager.load(want, progress=lambda p, m: print(f"  {p:3d}% {m}"))
            msg = f"OK loaded frida {mod.__version__} (requested {want})"
            log.info("frida-selftest: %s", msg)
            print(msg)
            return 0
        except Exception as exc:
            log.error("frida-selftest FAILED for %s: %s", want, exc)
            print(f"FAILED: {exc}")
            return 1
    initial = argv[0] if argv and argv[0].lower().endswith(".ipa") else None
    try:
        return _run_gui(initial)
    except Exception:
        log.critical("Fatal error starting GUI", exc_info=True)
        raise


if __name__ == "__main__":
    raise SystemExit(main())
