"""Fill the dashboard database with the demo devices and simulated events.

    python -m dashboard.seed            # same as python -m gateway.simulate
"""
from gateway.simulate import main

if __name__ == "__main__":
    main()
