import sys

try:
    from ispatched.cli import main
except ImportError:  # CLI arrives in a later task
    def main(argv=None):
        sys.stderr.write("ispatched: CLI not available yet\n")
        return 2

if __name__ == "__main__":
    sys.exit(main())
