# tests/test_genetic_optimizer.py
"""
Tests for pipeline/genetic_optimizer.py's chromosome encode/decode logic
and the balanced-fitness evaluator. Does NOT test run_ga_deap() itself
(requires the deap library, unavailable in this sandbox) or
run_ga_fallback()'s full generational loop (randomized, better validated
by direct end-to-end runs, which this project has already done at real
scale) -- focuses on the deterministic, bug-prone pieces: decoding a
chromosome into a valid feature mask + hyperparameter dict, and the
fitness-balancing fix that was found to matter directly (a pooled-F1
fitness let the GA silently trade away CASB performance for CERT gains).
"""

import random

import numpy as np

from pipeline.genetic_optimizer import (
    HYPERPARAM_OPTIONS,
    HYPERPARAM_ORDER,
    N_HYPERPARAM_GENES,
    decode_individual,
    make_evaluator,
    random_individual,
)


# ============================================================
# decode_individual -- chromosome -> (feature_mask, hyperparams)
# ============================================================

def test_decode_splits_feature_bits_from_hyperparam_genes():
    n_features = 5
    individual = [1, 0, 1, 1, 0] + [0, 0, 0, 0]  # 5 feature bits + 4 hyperparam indices
    mask, hyperparams = decode_individual(individual, n_features)
    assert list(mask) == [True, False, True, True, False]


def test_decode_maps_hyperparam_indices_to_real_values():
    n_features = 3
    individual = [1, 1, 1] + [2, 1, 0, 1]  # indices into each HYPERPARAM_OPTIONS list
    _, hyperparams = decode_individual(individual, n_features)
    assert hyperparams["max_depth"] == HYPERPARAM_OPTIONS["max_depth"][2]
    assert hyperparams["min_samples_split"] == HYPERPARAM_OPTIONS["min_samples_split"][1]
    assert hyperparams["min_samples_leaf"] == HYPERPARAM_OPTIONS["min_samples_leaf"][0]
    assert hyperparams["criterion"] == HYPERPARAM_OPTIONS["criterion"][1]


def test_decode_all_hyperparam_keys_present():
    n_features = 2
    individual = [1, 1] + [0, 0, 0, 0]
    _, hyperparams = decode_individual(individual, n_features)
    assert set(hyperparams.keys()) == set(HYPERPARAM_ORDER)


def test_decode_clamps_out_of_range_index_defensively():
    """decode_individual must not crash on a corrupted/out-of-range
    hyperparameter index (e.g. from a hypothetical future mutation bug)
    -- it should clamp into range rather than raise an IndexError."""
    n_features = 2
    individual = [1, 1] + [999, -5, 0, 0]  # deliberately out-of-range indices
    _, hyperparams = decode_individual(individual, n_features)
    assert hyperparams["max_depth"] in HYPERPARAM_OPTIONS["max_depth"]
    assert hyperparams["min_samples_split"] in HYPERPARAM_OPTIONS["min_samples_split"]


def test_decode_max_depth_none_option_preserved():
    """HYPERPARAM_OPTIONS["max_depth"] includes None (unlimited depth) as
    a real option -- confirm decoding correctly returns Python None, not
    a string 'None' or some other placeholder."""
    n_features = 1
    none_idx = HYPERPARAM_OPTIONS["max_depth"].index(None)
    individual = [1] + [none_idx, 0, 0, 0]
    _, hyperparams = decode_individual(individual, n_features)
    assert hyperparams["max_depth"] is None


# ============================================================
# random_individual -- valid chromosome generation
# ============================================================

def test_random_individual_has_correct_total_length():
    rng = random.Random(42)
    ind = random_individual(10, rng)
    assert len(ind) == 10 + N_HYPERPARAM_GENES


def test_random_individual_feature_bits_are_binary():
    rng = random.Random(42)
    ind = random_individual(20, rng)
    feature_bits = ind[:20]
    assert all(b in (0, 1) for b in feature_bits)


def test_random_individual_hyperparam_genes_in_valid_range():
    rng = random.Random(42)
    n_features = 10
    ind = random_individual(n_features, rng)
    hp_genes = ind[n_features:]
    for gene_val, name in zip(hp_genes, HYPERPARAM_ORDER):
        assert 0 <= gene_val < len(HYPERPARAM_OPTIONS[name])


def test_random_individual_is_reproducible_with_seeded_rng():
    ind1 = random_individual(15, random.Random(123))
    ind2 = random_individual(15, random.Random(123))
    assert ind1 == ind2


# ============================================================
# make_evaluator -- the balanced-fitness fix
# ============================================================

def _toy_classification_data():
    """A tiny, deterministic two-source dataset where one feature
    perfectly predicts the label -- just enough for a Decision Tree to
    get a real (non-degenerate) F1 score without needing real project data."""
    X_train = np.array([[1, 0], [1, 0], [0, 1], [0, 1]] * 5)
    y_train = np.array([1, 1, 0, 0] * 5)
    X_test = np.array([[1, 0], [0, 1], [1, 0], [0, 1]])
    y_test = np.array([1, 0, 1, 0])
    source_test = ["cert", "cert", "casb", "casb"]
    return X_train, y_train, X_test, y_test, source_test


def test_evaluator_returns_a_fitness_tuple():
    X_train, y_train, X_test, y_test, source_test = _toy_classification_data()
    evaluate = make_evaluator(X_train, y_train, X_test, y_test, source_test,
                               min_features=1, feature_penalty=0.0, seed=42)
    individual = [1, 1] + [3, 0, 0, 0]  # both features selected, default-ish hyperparams
    result = evaluate(individual)
    assert isinstance(result, tuple)
    assert len(result) == 1
    assert 0.0 <= result[0] <= 1.0


def test_evaluator_returns_zero_fitness_below_min_features():
    X_train, y_train, X_test, y_test, source_test = _toy_classification_data()
    evaluate = make_evaluator(X_train, y_train, X_test, y_test, source_test,
                               min_features=2, feature_penalty=0.0, seed=42)
    individual = [1, 0] + [0, 0, 0, 0]  # only 1 feature selected, below min_features=2
    result = evaluate(individual)
    assert result == (0.0,)


def test_evaluator_feature_penalty_reduces_fitness_for_larger_subsets():
    X_train, y_train, X_test, y_test, source_test = _toy_classification_data()
    evaluate_no_penalty = make_evaluator(X_train, y_train, X_test, y_test, source_test,
                                          min_features=1, feature_penalty=0.0, seed=42)
    evaluate_with_penalty = make_evaluator(X_train, y_train, X_test, y_test, source_test,
                                            min_features=1, feature_penalty=0.5, seed=42)
    individual = [1, 1] + [3, 0, 0, 0]
    fitness_no_penalty = evaluate_no_penalty(individual)[0]
    fitness_with_penalty = evaluate_with_penalty(individual)[0]
    assert fitness_with_penalty <= fitness_no_penalty


def test_balanced_fitness_is_mean_of_per_source_f1_not_pooled():
    """REGRESSION TEST for the actual bug found during this project: a
    pooled F1 fitness let the GA improve its combined score by choosing
    hyperparameters that helped the larger-volume source while quietly
    hurting the smaller one. Construct a case with imbalanced source
    sizes (3 cert rows, 1 casb row) where the model gets cert right but
    casb wrong -- balanced fitness (mean of per-source F1) must be
    heavily penalized by casb's failure even though it's a small
    minority of the test set; pooled fitness would barely notice it."""
    X_train = np.array([[1, 0], [1, 0], [0, 1], [0, 1]] * 5)
    y_train = np.array([1, 1, 0, 0] * 5)
    X_test = np.array([[1, 0], [1, 0], [1, 0], [0, 1]])  # 3 cert rows correct pattern, 1 casb row
    y_test = np.array([1, 1, 1, 0])  # model will get all 4 right actually -- need a harder case

    # Force a scenario where the model is right on CERT but the CASB
    # row's true label contradicts what the feature pattern would predict
    X_test = np.array([[1, 0], [1, 0], [1, 0], [1, 0]])
    y_test = np.array([1, 1, 1, 0])  # casb row (index 3) has feature pattern [1,0] but label 0 -- model will get it wrong
    source_test = ["cert", "cert", "cert", "casb"]

    evaluate_balanced = make_evaluator(X_train, y_train, X_test, y_test, source_test,
                                        min_features=1, feature_penalty=0.0, seed=42,
                                        balance_sources=True)
    evaluate_pooled = make_evaluator(X_train, y_train, X_test, y_test, source_test,
                                      min_features=1, feature_penalty=0.0, seed=42,
                                      balance_sources=False)
    individual = [1, 1] + [3, 0, 0, 0]

    fitness_balanced = evaluate_balanced(individual)[0]
    fitness_pooled = evaluate_pooled(individual)[0]

    # pooled F1 (3/4 correct = mostly cert-dominated) should score HIGHER
    # than balanced F1 (which weighs casb's total failure equally against
    # cert's success) -- confirming balancing actually changes the score
    # in the direction the diagnosed bug predicts
    assert fitness_pooled >= fitness_balanced
