"""Unit tests for metrics registry."""
import unittest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../c2"))
from observability.metrics import Counter, Gauge, Histogram, MetricsRegistry


class TestCounter(unittest.TestCase):
    def test_increment(self):
        c = Counter("test_counter", "help", ["label"])
        c.inc({"label": "a"})
        c.inc({"label": "a"})
        c.inc({"label": "b"})
        output = c.render()
        self.assertIn('test_counter{label="a"} 2.0', output)
        self.assertIn('test_counter{label="b"} 1.0', output)

    def test_no_labels(self):
        c = Counter("simple", "help", [])
        c.inc({})
        c.inc({}, amount=4.0)
        self.assertIn("simple 5.0", c.render())


class TestGauge(unittest.TestCase):
    def test_set(self):
        g = Gauge("test_gauge", "help", ["status"])
        g.set(42, {"status": "ok"})
        self.assertIn('test_gauge{status="ok"} 42', g.render())

    def test_inc_dec(self):
        g = Gauge("test_gauge2", "help")
        g.inc()
        g.inc()
        g.dec()
        self.assertIn("test_gauge2 1", g.render())


class TestHistogram(unittest.TestCase):
    def test_observe(self):
        h = Histogram("latency", "help", ["path"], buckets=[10, 50, 100, float("inf")])
        h.observe(5.0,  {"path": "/api"})
        h.observe(25.0, {"path": "/api"})
        h.observe(75.0, {"path": "/api"})
        out = h.render()
        self.assertIn('le="10"', out)
        self.assertIn('le="+Inf"', out)
        self.assertIn("latency_count", out)
        self.assertIn("latency_sum", out)

    def test_count_and_sum(self):
        h = Histogram("h2", "help", ["x"], buckets=[100, float("inf")])
        h.observe(10, {"x": "y"})
        h.observe(20, {"x": "y"})
        out = h.render()
        self.assertIn("h2_count", out)
        # sum should be 30
        self.assertIn("30.000", out)


class TestRegistry(unittest.TestCase):
    def test_render_all(self):
        reg = MetricsRegistry()
        c = reg.register(Counter("rc", "help", ["k"]))
        c.inc({"k": "v"})
        g = reg.register(Gauge("rg", "help"))
        g.set(7)
        output = reg.render_all()
        self.assertIn("rc", output)
        self.assertIn("rg", output)
        self.assertIn("7", output)


if __name__ == "__main__":
    unittest.main()
