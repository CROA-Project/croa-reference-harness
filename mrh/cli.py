import argparse
import sys
from . import __version__
from . import scenarios

def print_result(result):
    name, ok, detail = result
    print("[%s] %s\n        %s" % ("PASS" if ok else "FAIL", name, detail))
    return ok

def run_demo(demo_type):
    if demo_type == "permit":
        print("CROA demo: permit")
        return print_result(scenarios.positive_path())
    elif demo_type == "replay":
        print("CROA demo: replay")
        return print_result(scenarios.nt003_replay_blocked())
    elif demo_type == "deny":
        print("CROA demo: deny \u2014 trajectory hard limit")
        return print_result(scenarios.nt006())

def run_test():
    print("CROA Reference Harness \u2014 self-test\n" + "-" * 66)
    passed = 0
    for fn in scenarios.ALL:
        passed += bool(print_result(fn()))
    print("-" * 66)
    print("%d/%d scenarios passed" % (passed, len(scenarios.ALL)))
    return passed == len(scenarios.ALL)

def main(argv=None):
    parser = argparse.ArgumentParser(prog="croa")
    parser.add_argument("--version", action="version", version="croa " + __version__)

    subparsers = parser.add_subparsers(dest="command")

    demo_parser = subparsers.add_parser("demo")
    demo_parser.add_argument("type", nargs="?", choices=["permit", "replay", "deny"], default="permit")

    test_parser = subparsers.add_parser("test")

    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        return e.code

    if args.command == "demo":
        ok = run_demo(args.type)
        return 0 if ok else 1
    elif args.command == "test":
        ok = run_test()
        return 0 if ok else 1
    else:
        parser.print_help()
        return 2

if __name__ == "__main__":
    sys.exit(main())
