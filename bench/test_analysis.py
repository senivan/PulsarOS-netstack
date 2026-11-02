#!/usr/bin/env python3
"""Regression decisions use paired samples and explicit limiting conditions."""
import unittest
from analysis.report import regressions


class RegressionTests(unittest.TestCase):
    def evaluate(self, current=50, old=100, receiver_drops=0, repetitions=7, rate=0, app=False):
        def rows(engine, value):
            return [dict(case='test', engine=engine, repetition=i, group='application' if app else 'forward',
                         metric_value=value, offered_pps=200, receiver_kernel_drops=receiver_drops,
                         configured_rate_pps=rate) for i in range(repetitions)]
        return regressions({('test','current'):rows('current',current),('test','before'):rows('before',old)},
                           [dict(case='test',engine='current',median=current)],.20)[0]

    def test_reproducible_decline_fails(self):
        self.assertTrue(self.evaluate()['fail'])

    def test_insufficient_repetitions(self):
        self.assertFalse(self.evaluate(repetitions=1)['fail'])

    def test_receiver_limit_is_inconclusive(self):
        self.assertTrue(self.evaluate(receiver_drops=1)['inconclusive'])

    def test_fixed_rate_is_inconclusive(self):
        self.assertTrue(self.evaluate(rate=1000)['inconclusive'])

    def test_small_change_passes(self):
        self.assertFalse(self.evaluate(current=90)['fail'])

    def test_application_comparison(self):
        self.assertTrue(self.evaluate(app=True)['fail'])


if __name__=='__main__':
    unittest.main()
