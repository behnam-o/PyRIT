# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""
Probabilistic (threshold-based) tests.

Some behaviors are inherently stochastic, so a single pass/fail assertion is too
brittle. The ``@pytest.mark.probabilistic`` marker (implemented in
``tests/unit/conftest.py``) runs the test body many times and treats the whole
thing as a SINGLE reported test that passes only if the observed pass rate meets
``min_pass_rate``. The process exit code reflects that threshold outcome.

Write the body as an ordinary single-trial test; the marker handles the repetition.
"""

import random

import pytest


@pytest.mark.probabilistic(runs=200, min_pass_rate=0.4)
def test_random_value_under_half():
    """
    A single trial passes when a uniform random value is under 0.5, so the
    long-run pass rate is ~50%. A ``min_pass_rate`` at or below 0.5 (0.4 here,
    for a comfortable margin) most likely passes; requiring ~0.8 (see below)
    most likely fails. Setting it to exactly 0.5 would be a coin flip.
    """
    assert random.random() < 0.5


# @pytest.mark.xfail(reason="Demonstrates the failing threshold mode; ~50% pass rate < 0.8 required.")
@pytest.mark.probabilistic(runs=200, min_pass_rate=0.8)
def test_random_value_under_half_high_threshold():
    """Same ~50% pass rate, but the 0.8 threshold makes the aggregate test fail."""
    assert random.random() < 0.5
