"""Unit tests for CircuitBreaker."""
import time
import unittest
from unittest.mock import patch
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../c2"))
from resilience.circuit_breaker import CircuitBreaker, CircuitOpenError, CircuitState


class TestCircuitBreaker(unittest.TestCase):

    def _cb(self, threshold=3, recovery=1.0):
        return CircuitBreaker("test", failure_threshold=threshold,
                              recovery_timeout=recovery)

    def test_starts_closed(self):
        cb = self._cb()
        self.assertEqual(cb.state, CircuitState.CLOSED)

    def test_successful_calls_stay_closed(self):
        cb = self._cb()
        for _ in range(10):
            with cb:
                pass   # no exception
        self.assertEqual(cb.state, CircuitState.CLOSED)

    def test_trips_after_threshold_failures(self):
        cb = self._cb(threshold=3)
        for _ in range(3):
            try:
                with cb:
                    raise ValueError("simulated failure")
            except ValueError:
                pass
        self.assertEqual(cb.state, CircuitState.OPEN)

    def test_open_circuit_raises_immediately(self):
        cb = self._cb(threshold=1)
        try:
            with cb:
                raise RuntimeError("trip")
        except RuntimeError:
            pass
        with self.assertRaises(CircuitOpenError):
            with cb:
                pass   # Should not execute

    def test_transitions_to_half_open_after_timeout(self):
        cb = self._cb(threshold=1, recovery=0.05)
        try:
            with cb:
                raise RuntimeError("trip")
        except RuntimeError:
            pass
        self.assertEqual(cb.state, CircuitState.OPEN)
        time.sleep(0.1)
        self.assertEqual(cb.state, CircuitState.HALF_OPEN)

    def test_closes_after_successful_probe(self):
        cb = self._cb(threshold=1, recovery=0.05)
        try:
            with cb:
                raise RuntimeError("trip")
        except RuntimeError:
            pass
        time.sleep(0.1)
        # Probe succeeds
        with cb:
            pass
        self.assertEqual(cb.state, CircuitState.CLOSED)

    def test_reopens_on_failure_in_half_open(self):
        cb = self._cb(threshold=1, recovery=0.05)
        try:
            with cb:
                raise RuntimeError("trip")
        except RuntimeError:
            pass
        time.sleep(0.1)
        # Probe fails
        try:
            with cb:
                raise RuntimeError("probe fail")
        except RuntimeError:
            pass
        self.assertEqual(cb.state, CircuitState.OPEN)

    def test_decorator_syntax(self):
        cb = self._cb(threshold=2)
        call_count = {"n": 0}

        @cb.protect
        def flaky():
            call_count["n"] += 1
            raise IOError("fail")

        for _ in range(2):
            try: flaky()
            except IOError: pass

        # Circuit is now open
        with self.assertRaises(CircuitOpenError):
            flaky()

    def test_manual_reset(self):
        cb = self._cb(threshold=1)
        try:
            with cb:
                raise RuntimeError("trip")
        except RuntimeError:
            pass
        self.assertEqual(cb.state, CircuitState.OPEN)
        cb.reset()
        self.assertEqual(cb.state, CircuitState.CLOSED)

    def test_trip_count_increments(self):
        cb = self._cb(threshold=1)
        for _ in range(3):
            cb.reset()
            try:
                with cb:
                    raise RuntimeError()
            except RuntimeError:
                pass
        self.assertEqual(cb.total_trips, 3)

    def test_expected_errors_filter(self):
        cb = CircuitBreaker("test", failure_threshold=1,
                            expected_errors=(IOError,))
        # ValueError should NOT trip the circuit
        try:
            with cb:
                raise ValueError("not expected")
        except ValueError:
            pass
        self.assertEqual(cb.state, CircuitState.CLOSED)

        # IOError SHOULD trip it
        try:
            with cb:
                raise IOError("expected")
        except IOError:
            pass
        self.assertEqual(cb.state, CircuitState.OPEN)


if __name__ == "__main__":
    unittest.main()
