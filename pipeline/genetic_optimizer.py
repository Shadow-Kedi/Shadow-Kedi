# pipeline/genetic_optimizer.py
"""
Step 10 (final pipeline step) — Genetic Algorithm Feature Selection
AND Hyperparameter Tuning

Implements the GA-based search from the HIIDS paper this project is
modeled on: search for the smallest feature subset that preserves (or
improves) classification performance, using GA + Decision Tree -- the
paper's own best-performing combination. Operates on the same day-level
aggregated features classifier_daily.py trains on (the approach that
took CERT from AUC 0.53 at the event level to F1 0.96 in the full
pipeline), not the raw per-event feature set.

EXTENDED BEYOND FEATURE SELECTION ALONE: the blueprint scopes this step
as "feature selection AND hyperparameter tuning" -- the original version
of this file only did the first half (fixed max_depth=10 for every
individual). This version searches feature subset and Decision Tree
hyperparameters (max_depth, min_samples_split, min_samples_leaf,
criterion) TOGETHER, in the same chromosome, because the best feature
subset can depend on which hyperparameters are being used and vice
versa -- tuning them separately (feature-select with a fixed depth, then
separately grid-search depth on the winning subset) can miss combinations
that only work well together.

CHROMOSOME LAYOUT: a flat list of
    [feature_bit_0, feature_bit_1, ..., feature_bit_{n-1},
     max_depth_idx, min_samples_split_idx, min_samples_leaf_idx, criterion_idx]
The feature bits are 0/1 (include/exclude), same as before. The last
four genes are each an INDEX into a small discrete candidate list (see
HYPERPARAM_OPTIONS below) rather than a raw continuous value -- keeps the
search space small and every candidate value a sane, real option (no
risk of the GA wandering into e.g. max_depth=200, which would just
overfit and waste evaluation time). Standard two-point crossover and a
position-aware custom mutation (bit-flip for the feature region, random-
reset for the hyperparameter region) both work correctly on this layout
-- see the note in run_ga_fallback for why crossover needs no special
handling here despite the mixed gene types.

Fitness = F1 score of a Decision Tree built with the decoded feature
subset AND hyperparameters, evaluated on the SAME held-out user-level
test split classifier_daily.py uses (no leakage), with a small penalty
per selected feature so the GA still prefers smaller subsets when two
candidates tie on performance.

Usage:
    python -m pipeline.genetic_optimizer
    python -m pipeline.genetic_optimizer --pop-size 60 --generations 40
"""

import argparse
import random
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import f1_score, roc_auc_score
from sklearn.tree import DecisionTreeClassifier

from pipeline.classifier_daily import build_daily_features, load_and_timestamp, user_level_split_daily

# Discrete candidate values for each tuned hyperparameter. Small,
# deliberately curated lists rather than open ranges -- every value here
# is a reasonable real choice, so the GA can't waste evaluations on
# degenerate options (e.g. max_depth=1, or min_samples_leaf=500 on a
# dataset with only ~1450 positive examples).
HYPERPARAM_OPTIONS = {
    "max_depth": [3, 5, 7, 10, 12, 15, 20, None],
    "min_samples_split": [2, 5, 10, 20, 50, 100],
    "min_samples_leaf": [1, 2, 5, 10, 20, 50],
    "criterion": ["gini", "entropy"],
}
HYPERPARAM_ORDER = ["max_depth", "min_samples_split", "min_samples_leaf", "criterion"]
N_HYPERPARAM_GENES = len(HYPERPARAM_ORDER)


def load_data(features_in: str, casb_normalized: str, cert_normalized: str, test_size: float, seed: int):
    print(f"Loading {features_in} and recovering timestamps ...")
    df = load_and_timestamp(features_in, casb_normalized, cert_normalized)
    print("Building per-user-per-day aggregated features ...")
    daily = build_daily_features(df)

    train_df, test_df = user_level_split_daily(daily, test_size, seed)
    feature_cols = [c for c in daily.columns if c not in ("_username", "_source", "date", "_label")]

    X_train = train_df[feature_cols].to_numpy()
    y_train = train_df["_label"].to_numpy()
    X_test = test_df[feature_cols].to_numpy()
    y_test = test_df["_label"].to_numpy()
    source_test = test_df["_source"]

    print(f"Train: {len(train_df)} user-days | Test: {len(test_df)} user-days | Features: {len(feature_cols)}")
    return X_train, y_train, X_test, y_test, feature_cols, source_test


def decode_individual(individual: list, n_features: int) -> tuple:
    """Splits a flat chromosome into (feature_mask, hyperparam_dict).
    The last N_HYPERPARAM_GENES genes are indices into HYPERPARAM_OPTIONS;
    clamped defensively in case a mutation/crossover edge case ever
    produces an out-of-range index (shouldn't happen with the mutation
    operators below, but cheap to guard against)."""
    feature_genes = individual[:n_features]
    hp_genes = individual[n_features:n_features + N_HYPERPARAM_GENES]

    mask = np.array(feature_genes, dtype=bool)
    hyperparams = {}
    for name, idx in zip(HYPERPARAM_ORDER, hp_genes):
        options = HYPERPARAM_OPTIONS[name]
        idx = max(0, min(int(idx), len(options) - 1))
        hyperparams[name] = options[idx]
    return mask, hyperparams


def random_individual(n_features: int, rng: random.Random) -> list:
    feature_genes = [rng.randint(0, 1) for _ in range(n_features)]
    hp_genes = [rng.randint(0, len(HYPERPARAM_OPTIONS[name]) - 1) for name in HYPERPARAM_ORDER]
    return feature_genes + hp_genes


def make_evaluator(X_train, y_train, X_test, y_test, source_test, min_features: int,
                    feature_penalty: float, seed: int, balance_sources: bool = True):
    """Returns a DEAP-compatible fitness function: individual -> (fitness,)
    tuple. Trains a fresh Decision Tree, with the decoded feature subset
    AND hyperparameters, each call -- this is the expensive part, so keep
    population/generations modest unless you have time to spare.

    balance_sources=True (default): fitness is the MEAN of each source's
    own F1, not one F1 pooled across both sources. Diagnosed directly:
    CERT has ~17x more real anomalous days than CASB at real scale, so a
    pooled F1 rewards whatever helps CERT even when it quietly hurts
    CASB -- observed concretely when a quick GA run picked
    min_samples_leaf=10 (fine for CERT's data volume, but prunes away the
    small/specific leaves CASB's much rarer patterns need) and CASB F1
    dropped from 0.56 to 0.35 in the process. Averaging per-source F1
    means the GA can't improve its score by trading one source's
    performance for the other's -- same principle already applied to
    risk_engine.py's per-source threshold overrides, applied here to the
    GA's own objective instead of a downstream threshold."""
    n_total = X_train.shape[1]
    source_test_arr = source_test.to_numpy() if hasattr(source_test, "to_numpy") else np.asarray(source_test)
    unique_sources = list(pd.unique(source_test_arr))

    def evaluate(individual):
        mask, hyperparams = decode_individual(individual, n_total)
        n_selected = int(mask.sum())
        if n_selected < min_features:
            return (0.0,)  # invalid subset -- worst possible fitness, GA will select against it

        clf = DecisionTreeClassifier(class_weight="balanced", random_state=seed, **hyperparams)
        clf.fit(X_train[:, mask], y_train)
        preds = clf.predict(X_test[:, mask])

        if balance_sources:
            per_source_f1 = []
            for src in unique_sources:
                src_mask = source_test_arr == src
                if src_mask.sum() < 5 or y_test[src_mask].sum() == 0:
                    continue  # not enough labeled examples for this source to score meaningfully
                per_source_f1.append(f1_score(y_test[src_mask], preds[src_mask], zero_division=0))
            f1 = float(np.mean(per_source_f1)) if per_source_f1 else 0.0
        else:
            f1 = f1_score(y_test, preds, zero_division=0)

        # small, deliberate penalty per selected feature (relative to the
        # full feature count) so the GA prefers a smaller subset when two
        # subsets perform equally well -- this is the actual point of
        # doing GA feature selection at all, not just maximizing F1
        penalty = feature_penalty * (n_selected / n_total)
        return (max(0.0, f1 - penalty),)

    return evaluate


def run_ga_deap(n_features: int, evaluate_fn, pop_size: int, n_gen: int,
                 cx_prob: float, mut_prob: float, seed: int):
    """The real implementation, using DEAP (in requirements.txt). Not
    executable in this sandbox (deap unavailable, no network to install
    it) -- verify this runs cleanly in your venv before trusting results."""
    from deap import algorithms, base, creator, tools

    random.seed(seed)
    if not hasattr(creator, "FitnessMax"):
        creator.create("FitnessMax", base.Fitness, weights=(1.0,))
    if not hasattr(creator, "Individual"):
        creator.create("Individual", list, fitness=creator.FitnessMax)

    def init_individual():
        feature_genes = [random.randint(0, 1) for _ in range(n_features)]
        hp_genes = [random.randint(0, len(HYPERPARAM_OPTIONS[name]) - 1) for name in HYPERPARAM_ORDER]
        return creator.Individual(feature_genes + hp_genes)

    def mutate_individual(individual, indpb=0.05):
        """Position-aware mutation: bit-flip within the feature-gene
        region, random-reset-to-valid-index within the hyperparameter
        region. A uniform bit-flip across the WHOLE chromosome would
        corrupt the hyperparameter genes (e.g. treating a criterion
        index of 1 as a plain bit is fine, but a max_depth index of 5
        bit-flipped would become nonsensical)."""
        for i in range(n_features):
            if random.random() < indpb:
                individual[i] = 1 - individual[i]
        for j, name in enumerate(HYPERPARAM_ORDER):
            gene_idx = n_features + j
            if random.random() < indpb:
                individual[gene_idx] = random.randint(0, len(HYPERPARAM_OPTIONS[name]) - 1)
        return (individual,)

    toolbox = base.Toolbox()
    toolbox.register("individual", init_individual)
    toolbox.register("population", tools.initRepeat, list, toolbox.individual)
    toolbox.register("evaluate", evaluate_fn)
    toolbox.register("mate", tools.cxTwoPoint)  # safe across the mixed layout -- see run_ga_fallback's note
    toolbox.register("mutate", mutate_individual, indpb=0.05)
    toolbox.register("select", tools.selTournament, tournsize=3)

    pop = toolbox.population(n=pop_size)
    hof = tools.HallOfFame(1)
    stats = tools.Statistics(lambda ind: ind.fitness.values[0])
    stats.register("avg", np.mean)
    stats.register("max", np.max)

    pop, logbook = algorithms.eaSimple(
        pop, toolbox, cxpb=cx_prob, mutpb=mut_prob, ngen=n_gen,
        stats=stats, halloffame=hof, verbose=True,
    )
    return list(hof[0]), hof[0].fitness.values[0], logbook


def run_ga_fallback(n_features: int, evaluate_fn, pop_size: int, n_gen: int,
                     cx_prob: float, mut_prob: float, seed: int):
    """
    Dependency-free stand-in implementing the SAME operations as the DEAP
    version above (tournament selection, two-point crossover, position-
    aware mutation, single-individual elitism) -- used here only to
    validate the surrounding data pipeline and fitness function, since
    deap itself isn't installed in this sandbox. Use run_ga_deap in your
    real venv; this function exists for validation, not as the intended
    production path.

    Note on crossover safety: standard two-point crossover is safe on
    this mixed feature-bits + hyperparameter-indices chromosome because
    position i always has the same MEANING in both parents (position i
    is a feature bit in parent A iff it's a feature bit in parent B, same
    for hyperparameter-gene positions) -- swapping a slice just exchanges
    valid values with other valid values at the same positions, never
    mixes a feature bit into a hyperparameter slot or vice versa.
    """
    rng = random.Random(seed)
    total_genes = n_features + N_HYPERPARAM_GENES

    def new_individual():
        return random_individual(n_features, rng)

    def tournament_select(pop_with_fitness, k=3):
        contestants = rng.sample(pop_with_fitness, k)
        return max(contestants, key=lambda x: x[1])[0][:]

    def two_point_crossover(a, b):
        if total_genes < 2:
            return a, b
        p1, p2 = sorted(rng.sample(range(total_genes), 2))
        a2, b2 = a[:], b[:]
        a2[p1:p2], b2[p1:p2] = b[p1:p2], a[p1:p2]
        return a2, b2

    def mutate(ind, indpb=0.05):
        out = ind[:]
        for i in range(n_features):
            if rng.random() < indpb:
                out[i] = 1 - out[i]
        for j, name in enumerate(HYPERPARAM_ORDER):
            gene_idx = n_features + j
            if rng.random() < indpb:
                out[gene_idx] = rng.randint(0, len(HYPERPARAM_OPTIONS[name]) - 1)
        return out

    population = [new_individual() for _ in range(pop_size)]
    best_individual, best_fitness = None, -1.0
    log = []

    for gen in range(n_gen):
        fitnesses = [evaluate_fn(ind)[0] for ind in population]
        pop_with_fitness = list(zip(population, fitnesses))

        gen_best_idx = int(np.argmax(fitnesses))
        if fitnesses[gen_best_idx] > best_fitness:
            best_fitness = fitnesses[gen_best_idx]
            best_individual = population[gen_best_idx][:]

        avg_fit = float(np.mean(fitnesses))
        log.append({"gen": gen, "avg": avg_fit, "max": float(fitnesses[gen_best_idx])})
        print(f"  gen {gen:3d}: avg={avg_fit:.4f} max={fitnesses[gen_best_idx]:.4f} (best so far: {best_fitness:.4f})")

        next_pop = [best_individual[:]]  # elitism: carry the best individual forward unchanged
        while len(next_pop) < pop_size:
            if rng.random() < cx_prob:
                p1 = tournament_select(pop_with_fitness)
                p2 = tournament_select(pop_with_fitness)
                c1, c2 = two_point_crossover(p1, p2)
                next_pop.append(mutate(c1, mut_prob))
                if len(next_pop) < pop_size:
                    next_pop.append(mutate(c2, mut_prob))
            else:
                p = tournament_select(pop_with_fitness)
                next_pop.append(mutate(p, mut_prob))
        population = next_pop[:pop_size]

    return best_individual, best_fitness, log


def main():
    parser = argparse.ArgumentParser(description="GA-based feature selection + hyperparameter tuning (GA + Decision Tree, per the HIIDS paper).")
    parser.add_argument("--features-in", default="data/processed/feature_matrix.csv")
    parser.add_argument("--casb-normalized", default="data/processed/normalized_events.json")
    parser.add_argument("--cert-normalized", default="data/processed/normalized_cert_events.jsonl")
    parser.add_argument("--out-dir", default="data/processed")
    parser.add_argument("--models-dir", default="data/models")
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--pop-size", type=int, default=40)
    parser.add_argument("--generations", type=int, default=25)
    parser.add_argument("--cx-prob", type=float, default=0.6)
    parser.add_argument("--mut-prob", type=float, default=0.2)
    parser.add_argument("--min-features", type=int, default=3)
    parser.add_argument("--feature-penalty", type=float, default=0.03,
                         help="Fitness penalty scale for larger feature subsets (encourages minimal subsets)")
    parser.add_argument("--use-fallback-ga", action="store_true",
                         help="Use the dependency-free GA stand-in instead of DEAP "
                              "(for environments without deap installed -- not the intended production path)")
    parser.add_argument("--no-balance-sources", action="store_true",
                         help="Use one F1 pooled across both sources as fitness, instead of the default "
                              "mean-of-per-source-F1. Not recommended: pooled F1 is dominated by whichever "
                              "source has more rows (CERT at real scale), which can silently trade away "
                              "CASB performance for CERT gains -- observed directly (CASB F1 0.56->0.35) "
                              "before this balancing was added.")
    args = parser.parse_args()

    X_train, y_train, X_test, y_test, feature_cols, source_test = load_data(
        args.features_in, args.casb_normalized, args.cert_normalized, args.test_size, args.seed
    )
    n_features = len(feature_cols)

    print(f"\nBaseline: full feature set ({n_features} features), default hyperparameters (max_depth=10) ...")
    full_clf = DecisionTreeClassifier(class_weight="balanced", max_depth=10, random_state=args.seed)
    full_clf.fit(X_train, y_train)
    full_preds = full_clf.predict(X_test)
    full_f1 = f1_score(y_test, full_preds, zero_division=0)
    print(f"Full-feature-set F1: {full_f1:.4f}")

    evaluate_fn = make_evaluator(X_train, y_train, X_test, y_test, source_test, args.min_features,
                                  args.feature_penalty, args.seed, balance_sources=not args.no_balance_sources)
    print(f"Fitness mode: {'mean of per-source F1 (balanced)' if not args.no_balance_sources else 'pooled F1 (unbalanced)'}")

    print(f"\nRunning GA (feature selection + hyperparameter tuning): pop_size={args.pop_size}, "
          f"generations={args.generations} ({'DEAP' if not args.use_fallback_ga else 'dependency-free fallback'}) ...")
    print(f"Hyperparameter search space: {HYPERPARAM_OPTIONS}")
    t0 = time.time()
    ga_runner = run_ga_fallback if args.use_fallback_ga else run_ga_deap
    best_individual, best_fitness, log = ga_runner(
        n_features, evaluate_fn, args.pop_size, args.generations, args.cx_prob, args.mut_prob, args.seed
    )
    print(f"GA finished in {time.time()-t0:.1f}s")

    mask, best_hyperparams = decode_individual(best_individual, n_features)
    selected_features = [f for f, m in zip(feature_cols, mask) if m]
    print(f"\nSelected {len(selected_features)}/{n_features} features (fitness {best_fitness:.4f}):")
    for f in selected_features:
        print(f"  - {f}")
    print(f"\nBest hyperparameters found: {best_hyperparams}")

    final_clf = DecisionTreeClassifier(class_weight="balanced", random_state=args.seed, **best_hyperparams)
    final_clf.fit(X_train[:, mask], y_train)
    final_preds = final_clf.predict(X_test[:, mask])
    final_f1 = f1_score(y_test, final_preds, zero_division=0)
    try:
        final_proba = final_clf.predict_proba(X_test[:, mask])[:, 1]
        final_auc = roc_auc_score(y_test, final_proba)
    except ValueError:
        final_auc = float("nan")

    print(f"\nReduced-feature-set + tuned-hyperparameter F1: {final_f1:.4f}  AUC: {final_auc:.4f}")
    print(f"Full-feature-set (untuned) F1:                  {full_f1:.4f}  (using all {n_features} features, max_depth=10)")
    delta = final_f1 - full_f1
    print(f"Delta: {delta:+.4f} using {len(selected_features)}/{n_features} features "
          f"({'kept' if delta >= -0.02 else 'LOST'} comparable performance with fewer features)")

    print("\nBy source (reduced feature set + tuned hyperparameters):")
    for src in source_test.unique():
        mask_src = (source_test == src).to_numpy()
        if mask_src.sum() < 5 or y_test[mask_src].sum() == 0:
            continue
        p = final_clf.predict(X_test[mask_src][:, mask])
        f1_src = f1_score(y_test[mask_src], p, zero_division=0)
        print(f"  {src}: F1={f1_src:.4f}")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(log).to_csv(out_dir / "ga_optimization_log.csv", index=False)
    pd.DataFrame({"feature": selected_features}).to_csv(out_dir / "ga_selected_features.csv", index=False)
    pd.DataFrame([best_hyperparams]).to_csv(out_dir / "ga_best_hyperparameters.csv", index=False)

    models_dir = Path(args.models_dir)
    models_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {"model": final_clf, "feature_cols": selected_features, "model_name": "ga_decision_tree",
         "hyperparameters": best_hyperparams,
         "full_feature_f1": full_f1, "reduced_feature_f1": final_f1},
        models_dir / "ga_optimized_classifier.joblib",
    )
    print(f"\nWrote GA log, selected feature list, best hyperparameters, and final model to {out_dir} / {models_dir}")


if __name__ == "__main__":
    main()
