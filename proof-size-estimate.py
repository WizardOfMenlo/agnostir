import argparse
import contextlib
import importlib.util
import io
import itertools
import math
from dataclasses import dataclass
from pathlib import Path

LOG_HASH_SIZE = 256
LOG_FIELD_SIZE = 256
FIELD_SIZE_LOG = 256
SECPARAM = 100
ETA = 2**6
ERA_DB = 0.0001
ERA_BLOCK_INV_RATE_HINT = 1.21
FIXED_ERA_STAGE0_R = 4
BUDGET_SCALE = 1.0
DISTANCE_TABLE_VERSION = 3


@dataclass(frozen=True)
class EraDistance:
    log_k: int
    r: int
    log_block_length: float
    inv_rate: float
    delta: float


@dataclass(frozen=True)
class BasefoldDistance:
    d: int
    c: int
    delta: float


@dataclass(frozen=True)
class CodeswitchContribution:
    field_elements: float
    hashes: int
    oracle_length: int


@dataclass(frozen=True)
class BasefoldContribution:
    field_elements: float
    hashes: int
    oracle_length: int
    rounds: int
    queries: int


@dataclass(frozen=True)
class SearchState:
    field_elements: float
    hashes: float
    oracle_length: int
    r_path: tuple[int, ...]

    @property
    def proof_units(self) -> float:
        return self.field_elements + self.hashes


@dataclass(frozen=True)
class Candidate:
    num_codeswitches: int
    eta: int
    k_exponents: tuple[int, ...]
    era_path: tuple[EraDistance, ...]
    basefold: BasefoldDistance
    basefold_rounds: int
    field_elements: float
    hashes: float
    codeswitch_oracle_length: int
    basefold_oracle_length: int

    @property
    def total_oracle_length(self) -> int:
        return self.codeswitch_oracle_length + self.basefold_oracle_length

    @property
    def proof_units(self) -> float:
        return self.field_elements + self.hashes


@dataclass(frozen=True)
class BaselineResult:
    eta: int
    k0_exp: int
    basefold: BasefoldDistance
    basefold_rounds: int
    starting_field_elements: float
    starting_hashes: int
    basefold_field_elements: float
    basefold_hashes: int
    basefold_oracle_length: int

    @property
    def field_elements(self) -> float:
        return self.starting_field_elements + self.basefold_field_elements

    @property
    def hashes(self) -> float:
        return self.starting_hashes + self.basefold_hashes

    @property
    def proof_units(self) -> float:
        return self.field_elements + self.hashes

    @property
    def total_oracle_length(self) -> int:
        return self.basefold_oracle_length


def load_module_from_path(module_name: str, path: Path):
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load module from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def merkle_tree_hashes(queries: int, n_depth: int) -> tuple[int, int]:
    top_levels = math.log2(queries)
    hashes_top = queries - 2
    hashes_sib = math.ceil((n_depth - top_levels) * queries)
    return hashes_top, hashes_sib


def num_queries_from_delta(delta: float, conjecture: bool = False) -> int:
    eps = delta if conjecture else (1 - (1 - delta) ** (1 / 3))
    return math.ceil(-SECPARAM / math.log2(1 - eps))


def compute_codeswitch_proof_size(
    in_r: int,
    in_inv_rate: float,
    out_delta: float,
    out_block_length: int,
    k: int,
    k_prime: int,
    conjecture: bool = False,
) -> CodeswitchContribution:
    # `in_inv_rate` is ERA inverse rate for the full code, so:
    #   block_length = k * in_inv_rate
    # and the inner-code blowup is inferred as b = in_inv_rate / r.
    n = in_inv_rate * k
    b = in_inv_rate / in_r
    indices = num_queries_from_delta(out_delta, conjecture)

    ell_m = math.ceil(k / k_prime)
    ell_b = math.ceil(b * k / k_prime)
    ell_g = math.ceil(math.sqrt(b) * k / k_prime)
    ell_era = math.ceil(in_inv_rate * k / k_prime)

    log_n_era_ceil = math.ceil(math.log2(n))
    term_1 = (2 * log_n_era_ceil + 1) * log_n_era_ceil
    term_2_5 = 5 * ell_m + 4 * ell_g + 4 * ell_b + 20 * ell_era
    term_6_8 = 8 + 3 * math.log2(k) + 4 * math.log2(k_prime)
    codeswitch_elements = term_1 + term_2_5 + term_6_8

    indexer_oracles = ell_g + 3 * ell_era
    online_oracles = ell_m + ell_b + 2 * ell_era
    indexer_elements = indexer_oracles * indices
    online_elements = online_oracles * indices

    top_b, sib_b = merkle_tree_hashes(indices, math.ceil(math.log2(out_block_length)))
    total_hashes = 2 * (top_b + sib_b)

    # Oracle length in field elements, explicitly requested by user:
    # (indexer_oracles + online_oracles) * out_block_length.
    oracle_length = (indexer_oracles + online_oracles) * out_block_length
    return CodeswitchContribution(
        field_elements=codeswitch_elements + indexer_elements + online_elements,
        hashes=total_hashes,
        oracle_length=oracle_length,
    )


def compute_basefold_contribution(
    log_message_length: int,
    final_message_exp: int,
    inv_rate: int,
    delta: float,
    conjecture: bool = False,
) -> BasefoldContribution:
    rounds = log_message_length - final_message_exp
    if rounds <= 0:
        raise ValueError(
            f"invalid rounds: log_message_length={log_message_length}, "
            f"final_message_exp={final_message_exp}"
        )

    queries = num_queries_from_delta(delta, conjecture)
    sumcheck_elements = rounds * 3
    queried_elements = rounds * 2 * queries
    base_case_elements = 2**final_message_exp
    total_basefold_elements = sumcheck_elements + queried_elements + base_case_elements

    top_total = 0
    sib_total = 0
    for n in range(final_message_exp + 1, log_message_length + 1):
        depth = n + math.ceil(math.log2(inv_rate)) - 1
        top_c, sib_c = merkle_tree_hashes(queries, depth)
        top_total += top_c
        sib_total += sib_c
    total_hashes = top_total + sib_total

    # Oracle length in field elements for basefold:
    # sum_t message_len_t * inv_rate, with message_len halved per round.
    message_len = 2**log_message_length
    oracle_length = 0
    for _ in range(rounds):
        oracle_length += message_len * inv_rate
        message_len //= 2

    return BasefoldContribution(
        field_elements=total_basefold_elements,
        hashes=total_hashes,
        oracle_length=oracle_length,
        rounds=rounds,
        queries=queries,
    )


def compute_starting_ior(
    k0: int,
    eta: int,
    era0: EraDistance,
    conjecture: bool = False,
) -> tuple[float, int]:
    return compute_starting_ior_for_code(k0, eta, era0.delta, era0.inv_rate, conjecture)


def compute_starting_ior_for_code(
    k0: int,
    eta: int,
    delta: float,
    inv_rate: float,
    conjecture: bool = False,
) -> tuple[float, int]:
    indices = num_queries_from_delta(delta, conjecture)
    field_elements = indices * eta + 3 * math.ceil(math.log2(k0 * eta))
    tree_depth = math.ceil(math.log2(k0 * inv_rate))
    top_a, sib_a = merkle_tree_hashes(indices, tree_depth)
    hashes = top_a + sib_a
    return field_elements, hashes


def total_oracle_length(
    codeswitch_oracle_lengths: list[int],
    basefold_oracle_length: int,
) -> tuple[int, int, int]:
    codeswitch_total = sum(codeswitch_oracle_lengths)
    return codeswitch_total, basefold_oracle_length, codeswitch_total + basefold_oracle_length


def is_power_of_two(value: int) -> bool:
    return value > 0 and (value & (value - 1)) == 0


def power_of_two_values(min_value: int, max_value: int) -> list[int]:
    return [value for value in range(min_value, max_value + 1) if is_power_of_two(value)]


def format_budget_label(budget: int) -> str:
    if is_power_of_two(budget):
        return f"2^{int(math.log2(budget))} ({budget})"
    return f"{budget} (~2^{math.log2(budget):.3f})"


def prune_states(states: list[SearchState], max_budget: int) -> list[SearchState]:
    filtered = [s for s in states if s.oracle_length <= max_budget]
    filtered.sort(key=lambda s: (s.oracle_length, s.proof_units))
    frontier: list[SearchState] = []
    best_units = math.inf
    for state in filtered:
        if state.proof_units < best_units:
            frontier.append(state)
            best_units = state.proof_units
    return frontier


def better_candidate(lhs: Candidate, rhs: Candidate | None) -> bool:
    if rhs is None:
        return True
    if lhs.proof_units < rhs.proof_units:
        return True
    if lhs.proof_units == rhs.proof_units and lhs.total_oracle_length < rhs.total_oracle_length:
        return True
    return False


def generate_k_exponent_sequences(
    num_codeswitches: int,
    start_k_exp: int,
    min_k_exp: int,
) -> list[tuple[int, ...]]:
    sequences: list[tuple[int, ...]] = []
    for middle in itertools.combinations_with_replacement(
        range(min_k_exp, start_k_exp + 1),
        num_codeswitches,
    ):
        seq = (start_k_exp,) + tuple(reversed(middle))
        if all(seq[i] >= seq[i + 1] for i in range(len(seq) - 1)):
            sequences.append(seq)
    return sequences


def candidate_start_k_eta_pairs(args) -> list[tuple[int, int]]:
    if args.optimize_k0:
        pairs: list[tuple[int, int]] = []
        for eta_exp in range(args.eta_min_exp, args.eta_max_exp + 1):
            start_k_exp = args.universal_message_exp - eta_exp
            if start_k_exp < args.min_k_exp:
                continue
            if start_k_exp <= args.final_message_exp:
                continue
            eta = 2**eta_exp
            pairs.append((start_k_exp, eta))
        return sorted(set(pairs))

    if args.start_k_exp > args.universal_message_exp:
        return []
    eta_exp = args.universal_message_exp - args.start_k_exp
    if not (args.eta_min_exp <= eta_exp <= args.eta_max_exp):
        return []
    return [(args.start_k_exp, 2**eta_exp)]


def solve_era_params(
    era_mod,
    log_k: int,
    r: int,
) -> EraDistance | None:
    era_inv_rate = ERA_BLOCK_INV_RATE_HINT * r
    # Use n = log2(k * inv_rate_era) with inv_rate_era = 1.21 * r.
    n_guess = log_k + math.log2(era_inv_rate)

    with contextlib.redirect_stdout(io.StringIO()):
        c = era_mod.compute_c_from_q_bound(
            r,
            SECPARAM,
            ERA_DB,
            n_guess,
            FIELD_SIZE_LOG,
        )
    if c is None:
        return None
    c = float(c)
    c_upper_bound = (r / 2) * (1 - 1 / math.sqrt(5))
    if not (1 < c < c_upper_bound):
        return None

    with contextlib.redirect_stdout(io.StringIO()):
        gamma = era_mod.compute_gamma_from_n_bound(r, c, SECPARAM, n_guess)
        delta = era_mod.solve_system(c, r, gamma, ERA_DB)
    if delta is None:
        return None
    delta = float(delta)
    if not (0 < delta < 1):
        return None
    return EraDistance(
        log_k=log_k,
        r=r,
        log_block_length=n_guess,
        inv_rate=era_inv_rate,
        delta=delta,
    )


def precompute_era_distances(
    era_mod,
    log_k_values: list[int],
    r_values: list[int],
) -> dict[tuple[int, int], EraDistance]:
    table: dict[tuple[int, int], EraDistance] = {}
    for log_k in log_k_values:
        for r in r_values:
            params = solve_era_params(era_mod, log_k, r)
            if params is not None:
                table[(log_k, r)] = params
    return table


def precompute_basefold_distances(
    basefold_mod,
    d_values: list[int],
    c_values: list[int],
) -> dict[tuple[int, int], BasefoldDistance]:
    table: dict[tuple[int, int], BasefoldDistance] = {}
    for d in d_values:
        for c in c_values:
            delta = float(basefold_mod.compute_formula(FIELD_SIZE_LOG, c, d, SECPARAM))
            if 0 < delta < 1:
                table[(d, c)] = BasefoldDistance(d=d, c=c, delta=delta)
    return table


def read_distance_table(
    path: Path,
) -> tuple[dict[str, str], dict[tuple[int, int], EraDistance], dict[tuple[int, int], BasefoldDistance]]:
    meta: dict[str, str] = {}
    era_table: dict[tuple[int, int], EraDistance] = {}
    basefold_table: dict[tuple[int, int], BasefoldDistance] = {}
    if not path.exists():
        return meta, era_table, basefold_table

    with path.open("r", encoding="ascii") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            if line.startswith("#"):
                if "=" in line:
                    payload = line.lstrip("# ").strip()
                    key, value = payload.split("=", 1)
                    meta[key.strip()] = value.strip()
                continue
            parts = line.split("\t")
            if parts[0] == "ERA" and len(parts) == 6:
                if parts[1] == "log_k":
                    continue
                log_k = int(parts[1])
                r = int(parts[2])
                era_table[(log_k, r)] = EraDistance(
                    log_k=log_k,
                    r=r,
                    log_block_length=float(parts[3]),
                    inv_rate=float(parts[4]),
                    delta=float(parts[5]),
                )
            if parts[0] == "BASEFOLD" and len(parts) == 4:
                if parts[1] == "d":
                    continue
                d = int(parts[1])
                c = int(parts[2])
                basefold_table[(d, c)] = BasefoldDistance(
                    d=d,
                    c=c,
                    delta=float(parts[3]),
                )
    return meta, era_table, basefold_table


def write_distance_table(
    path: Path,
    era_table: dict[tuple[int, int], EraDistance],
    basefold_table: dict[tuple[int, int], BasefoldDistance],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="ascii") as handle:
        handle.write(f"# distance_table_version={DISTANCE_TABLE_VERSION}\n")
        handle.write(f"# secparam={SECPARAM}\n")
        handle.write(f"# field_size_log2={FIELD_SIZE_LOG}\n")
        handle.write(f"# era_base_distance={ERA_DB}\n")
        handle.write("ERA\tlog_k\tr\tlog_block_length\tinv_rate\tdelta\n")
        for key in sorted(era_table):
            entry = era_table[key]
            handle.write(
                f"ERA\t{entry.log_k}\t{entry.r}\t{entry.log_block_length:.9f}\t"
                f"{entry.inv_rate:.9f}\t{entry.delta:.9f}\n"
            )
        handle.write("BASEFOLD\td\tc\tdelta\n")
        for key in sorted(basefold_table):
            entry = basefold_table[key]
            handle.write(f"BASEFOLD\t{entry.d}\t{entry.c}\t{entry.delta:.9f}\n")


def get_or_build_distance_tables(
    args,
) -> tuple[dict[tuple[int, int], EraDistance], dict[tuple[int, int], BasefoldDistance]]:
    basefold_c_values = power_of_two_values(args.basefold_c_min, args.basefold_c_max)
    start_k_eta_pairs = candidate_start_k_eta_pairs(args)
    if not start_k_eta_pairs:
        raise ValueError("No feasible (k0, eta) candidates under the current constraints")
    max_start_exp = max(start_k_exp for start_k_exp, _ in start_k_eta_pairs)
    required_era_keys = {
        (log_k, r)
        for log_k in range(args.min_k_exp, max_start_exp + 1)
        for r in range(args.era_r_min, args.era_r_max + 1)
    }
    required_basefold_keys = {
        (d, c)
        for d in range(args.min_k_exp, max_start_exp + 1)
        for c in basefold_c_values
    }

    meta, era_table, basefold_table = read_distance_table(args.distance_table_path)
    # Fast migration path from version 2 -> 3:
    # keep precomputed deltas, but update ERA inverse-rate semantics from
    # ceil(1.21 * r) to exact (1.21 * r), and adjust logged block length.
    if (
        meta.get("distance_table_version") == "2"
        and meta.get("secparam") == str(SECPARAM)
        and meta.get("field_size_log2") == str(FIELD_SIZE_LOG)
        and meta.get("era_base_distance") == str(ERA_DB)
        and era_table
        and basefold_table
    ):
        migrated_era: dict[tuple[int, int], EraDistance] = {}
        for (log_k, r), entry in era_table.items():
            inv_rate = ERA_BLOCK_INV_RATE_HINT * r
            migrated_era[(log_k, r)] = EraDistance(
                log_k=log_k,
                r=r,
                log_block_length=log_k + math.log2(inv_rate),
                inv_rate=inv_rate,
                delta=entry.delta,
            )
        write_distance_table(args.distance_table_path, migrated_era, basefold_table)
        return migrated_era, basefold_table

    metadata_matches = (
        meta.get("distance_table_version") == str(DISTANCE_TABLE_VERSION)
        and
        meta.get("secparam") == str(SECPARAM)
        and meta.get("field_size_log2") == str(FIELD_SIZE_LOG)
        and meta.get("era_base_distance") == str(ERA_DB)
    )
    tables_complete = required_era_keys.issubset(era_table) and required_basefold_keys.issubset(basefold_table)

    if metadata_matches and tables_complete:
        return era_table, basefold_table

    era_mod = load_module_from_path("era_distance_module", Path("distance-analysis/era.py"))
    basefold_mod = load_module_from_path("basefold_distance_module", Path("distance-analysis/basefold.py"))
    era_table = precompute_era_distances(
        era_mod,
        list(range(args.min_k_exp, max_start_exp + 1)),
        list(range(args.era_r_min, args.era_r_max + 1)),
    )
    basefold_table = precompute_basefold_distances(
        basefold_mod,
        list(range(args.min_k_exp, max_start_exp + 1)),
        basefold_c_values,
    )
    write_distance_table(args.distance_table_path, era_table, basefold_table)
    return era_table, basefold_table


def optimize_for_fixed_chain(
    num_codeswitches: int,
    eta: int,
    k_exponents: tuple[int, ...],
    era_by_k: dict[int, dict[int, EraDistance]],
    basefold: BasefoldDistance,
    budgets: list[int],
    final_message_exp: int,
    conjecture: bool,
) -> dict[int, Candidate | None]:
    best_for_budget: dict[int, Candidate | None] = {budget: None for budget in budgets}
    max_budget = max(budgets)

    era_layers: list[dict[int, EraDistance]] = []
    for log_k in k_exponents[:-1]:
        era_options = era_by_k.get(log_k, {})
        if not era_options:
            return best_for_budget
        era_layers.append(era_options)

    start_k = 2**k_exponents[0]
    frontier: dict[int, list[SearchState]] = {}
    era0 = era_layers[0].get(FIXED_ERA_STAGE0_R)
    if era0 is None:
        return best_for_budget
    field_start, hash_start = compute_starting_ior(start_k, eta, era0, conjecture)
    frontier[FIXED_ERA_STAGE0_R] = [
        SearchState(
            field_elements=field_start,
            hashes=hash_start,
            oracle_length=0,
            r_path=(FIXED_ERA_STAGE0_R,),
        )
    ]

    # Codeswitches with ERA outputs (all except final codeswitch to basefold).
    for stage in range(1, num_codeswitches):
        k_prev = 2**k_exponents[stage - 1]
        k_cur = 2**k_exponents[stage]
        next_frontier: dict[int, list[SearchState]] = {}

        for prev_r, states in frontier.items():
            prev_era = era_layers[stage - 1][prev_r]
            for cur_r, cur_era in era_layers[stage].items():
                out_block_len = math.ceil(k_cur * cur_era.inv_rate)
                contrib = compute_codeswitch_proof_size(
                    prev_era.r,
                    prev_era.inv_rate,
                    cur_era.delta,
                    out_block_len,
                    k_prev,
                    k_cur,
                    conjecture,
                )
                appended = next_frontier.setdefault(cur_r, [])
                for state in states:
                    appended.append(
                        SearchState(
                            field_elements=state.field_elements + contrib.field_elements,
                            hashes=state.hashes + contrib.hashes,
                            oracle_length=state.oracle_length + contrib.oracle_length,
                            r_path=state.r_path + (cur_r,),
                        )
                    )
        frontier = {r: prune_states(states, max_budget) for r, states in next_frontier.items() if states}
        if not frontier:
            return best_for_budget

    # Final codeswitch: ERA -> basefold.
    k_prev = 2**k_exponents[num_codeswitches - 1]
    k_last = 2**k_exponents[num_codeswitches]
    basefold_contrib = compute_basefold_contribution(
        k_exponents[num_codeswitches],
        final_message_exp,
        basefold.c,
        basefold.delta,
        conjecture,
    )

    for prev_r, states in frontier.items():
        prev_era = era_layers[num_codeswitches - 1][prev_r]
        out_block_len = math.ceil(k_last * basefold.c)
        final_cs = compute_codeswitch_proof_size(
            prev_era.r,
            prev_era.inv_rate,
            basefold.delta,
            out_block_len,
            k_prev,
            k_last,
            conjecture,
        )

        for state in states:
            codeswitch_oracle, basefold_oracle, total_oracle = total_oracle_length(
                [state.oracle_length, final_cs.oracle_length],
                basefold_contrib.oracle_length,
            )
            if total_oracle > max_budget:
                continue

            total_field = state.field_elements + final_cs.field_elements + basefold_contrib.field_elements
            total_hash = state.hashes + final_cs.hashes + basefold_contrib.hashes
            era_path = tuple(
                era_layers[idx][state.r_path[idx]]
                for idx in range(len(state.r_path))
            )
            candidate = Candidate(
                num_codeswitches=num_codeswitches,
                eta=eta,
                k_exponents=k_exponents,
                era_path=era_path,
                basefold=basefold,
                basefold_rounds=basefold_contrib.rounds,
                field_elements=total_field,
                hashes=total_hash,
                codeswitch_oracle_length=codeswitch_oracle,
                basefold_oracle_length=basefold_oracle,
            )

            for budget in budgets:
                if candidate.total_oracle_length <= budget and better_candidate(candidate, best_for_budget[budget]):
                    best_for_budget[budget] = candidate

    return best_for_budget


def optimize(
    args,
    era_table,
    basefold_table,
    budgets: list[int],
    conjecture: bool,
) -> tuple[dict[int, Candidate | None], dict[int, dict[int, Candidate | None]]]:
    best_global: dict[int, Candidate | None] = {budget: None for budget in budgets}
    per_codeswitch: dict[int, dict[int, Candidate | None]] = {
        num_codeswitches: {budget: None for budget in budgets}
        for num_codeswitches in range(args.min_codeswitches, args.max_codeswitches + 1)
    }

    era_by_k: dict[int, dict[int, EraDistance]] = {}
    for (log_k, r), entry in era_table.items():
        era_by_k.setdefault(log_k, {})[r] = entry

    start_k_eta_pairs = candidate_start_k_eta_pairs(args)

    for num_codeswitches in range(args.min_codeswitches, args.max_codeswitches + 1):
        for start_k_exp, eta in start_k_eta_pairs:
            k_sequences = generate_k_exponent_sequences(
                num_codeswitches=num_codeswitches,
                start_k_exp=start_k_exp,
                min_k_exp=args.min_k_exp,
            )
            for k_exponents in k_sequences:
                final_k_exp = k_exponents[-1]
                if final_k_exp <= args.final_message_exp:
                    continue
                basefold_candidates = [
                    basefold_table[(final_k_exp, c)]
                    for c in power_of_two_values(args.basefold_c_min, args.basefold_c_max)
                    if (final_k_exp, c) in basefold_table
                ]
                for basefold in basefold_candidates:
                    best_local = optimize_for_fixed_chain(
                        num_codeswitches=num_codeswitches,
                        eta=eta,
                        k_exponents=k_exponents,
                        era_by_k=era_by_k,
                        basefold=basefold,
                        budgets=budgets,
                        final_message_exp=args.final_message_exp,
                        conjecture=conjecture,
                    )
                    for budget in budgets:
                        local = best_local[budget]
                        if local is None:
                            continue
                        if better_candidate(local, per_codeswitch[num_codeswitches][budget]):
                            per_codeswitch[num_codeswitches][budget] = local
                        if better_candidate(local, best_global[budget]):
                            best_global[budget] = local

    return best_global, per_codeswitch


def better_baseline(lhs: BaselineResult, rhs: BaselineResult | None) -> bool:
    if rhs is None:
        return True
    if lhs.proof_units < rhs.proof_units:
        return True
    if lhs.proof_units == rhs.proof_units and lhs.total_oracle_length < rhs.total_oracle_length:
        return True
    return False


def optimize_baseline(
    args,
    basefold_table: dict[tuple[int, int], BasefoldDistance],
    budget: int,
    conjecture: bool,
) -> BaselineResult | None:
    # Baseline constraints from user:
    # - no codeswitch
    # - one code: basefold with inv rate c=2
    baseline_c = 2

    start_k_eta_pairs = candidate_start_k_eta_pairs(args)

    best: BaselineResult | None = None
    for k0_exp, eta in start_k_eta_pairs:
        if k0_exp <= args.final_message_exp:
            continue
        key = (k0_exp, baseline_c)
        if key not in basefold_table:
            continue
        basefold = basefold_table[key]
        k0 = 2**k0_exp

        starting_field, starting_hashes = compute_starting_ior_for_code(
            k0=k0,
            eta=eta,
            delta=basefold.delta,
            inv_rate=basefold.c,
            conjecture=conjecture,
        )
        basefold_contrib = compute_basefold_contribution(
            log_message_length=k0_exp,
            final_message_exp=args.final_message_exp,
            inv_rate=basefold.c,
            delta=basefold.delta,
            conjecture=conjecture,
        )
        if basefold_contrib.oracle_length > budget:
            continue
        candidate = BaselineResult(
            eta=eta,
            k0_exp=k0_exp,
            basefold=basefold,
            basefold_rounds=basefold_contrib.rounds,
            starting_field_elements=starting_field,
            starting_hashes=starting_hashes,
            basefold_field_elements=basefold_contrib.field_elements,
            basefold_hashes=basefold_contrib.hashes,
            basefold_oracle_length=basefold_contrib.oracle_length,
        )
        if better_baseline(candidate, best):
            best = candidate
    return best


def candidate_proof_size_kb(candidate: Candidate) -> float:
    field_kb = (candidate.field_elements * LOG_FIELD_SIZE) / 8 / 1000
    hash_kb = (candidate.hashes * LOG_HASH_SIZE) / 8 / 1000
    return field_kb + hash_kb


def baseline_proof_size_kb(baseline: BaselineResult) -> float:
    field_kb = (baseline.field_elements * LOG_FIELD_SIZE) / 8 / 1000
    hash_kb = (baseline.hashes * LOG_HASH_SIZE) / 8 / 1000
    return field_kb + hash_kb


def candidate_starting_ior_contribution(
    candidate: Candidate,
    conjecture: bool,
) -> tuple[float, int]:
    k0 = 2**candidate.k_exponents[0]
    return compute_starting_ior(k0, candidate.eta, candidate.era_path[0], conjecture)


def candidate_codeswitch_contributions(
    candidate: Candidate,
    conjecture: bool,
) -> tuple[CodeswitchContribution, ...]:
    contributions: list[CodeswitchContribution] = []
    # ERA -> ERA codeswitches.
    for stage in range(1, candidate.num_codeswitches):
        prev_era = candidate.era_path[stage - 1]
        cur_era = candidate.era_path[stage]
        k_prev = 2**candidate.k_exponents[stage - 1]
        k_cur = 2**candidate.k_exponents[stage]
        out_block_len = math.ceil(k_cur * cur_era.inv_rate)
        contributions.append(
            compute_codeswitch_proof_size(
                prev_era.r,
                prev_era.inv_rate,
                cur_era.delta,
                out_block_len,
                k_prev,
                k_cur,
                conjecture,
            )
        )

    # Final ERA -> Basefold codeswitch.
    prev_era = candidate.era_path[candidate.num_codeswitches - 1]
    k_prev = 2**candidate.k_exponents[candidate.num_codeswitches - 1]
    k_last = 2**candidate.k_exponents[candidate.num_codeswitches]
    out_block_len = math.ceil(k_last * candidate.basefold.c)
    contributions.append(
        compute_codeswitch_proof_size(
            prev_era.r,
            prev_era.inv_rate,
            candidate.basefold.delta,
            out_block_len,
            k_prev,
            k_last,
            conjecture,
        )
    )
    return tuple(contributions)


def candidate_basefold_contribution(
    candidate: Candidate,
    conjecture: bool,
) -> BasefoldContribution:
    log_message_length = candidate.k_exponents[candidate.num_codeswitches]
    final_message_exp = log_message_length - candidate.basefold_rounds
    return compute_basefold_contribution(
        log_message_length=log_message_length,
        final_message_exp=final_message_exp,
        inv_rate=candidate.basefold.c,
        delta=candidate.basefold.delta,
        conjecture=conjecture,
    )


def format_candidate(candidate: Candidate, budget: int, conjecture: bool) -> str:
    total_kb = candidate_proof_size_kb(candidate)
    start_field, start_hashes = candidate_starting_ior_contribution(candidate, conjecture)
    start_kb = ((start_field * LOG_FIELD_SIZE) + (start_hashes * LOG_HASH_SIZE)) / 8 / 1000
    start_share = 100.0 * start_kb / total_kb
    basefold_rate = 1.0 / candidate.basefold.c
    codeswitch_contribs = candidate_codeswitch_contributions(candidate, conjecture)
    basefold_contrib = candidate_basefold_contribution(candidate, conjecture)

    lines = [
        f"Oracle budget <= {format_budget_label(budget)} field elements",
        f"  proof size: {total_kb:.3f} KB ({total_kb / 1000:.6f} MB)",
        f"  field elements in proof: {candidate.field_elements:.3f}",
        f"  hashes in proof: {candidate.hashes:.3f}",
        (
            "  starting IOR contribution: "
            f"field_elements={start_field:.3f}, hashes={start_hashes}, "
            f"size={start_kb:.3f} KB ({start_share:.2f}% of proof)"
        ),
        (
            "  total oracle length: "
            f"{candidate.total_oracle_length} "
            f"(codeswitch={candidate.codeswitch_oracle_length}, "
            f"basefold={candidate.basefold_oracle_length})"
        ),
        f"  num codeswitches: {candidate.num_codeswitches}",
        f"  eta: {candidate.eta}",
        f"  k exponents: {candidate.k_exponents}",
        f"  k values: {tuple(2**exp for exp in candidate.k_exponents)}",
        f"  eta * k0: {candidate.eta * (2**candidate.k_exponents[0])}",
        (
            f"  basefold code: d={candidate.basefold.d}, c={candidate.basefold.c}, "
            f"rate={basefold_rate:.6f}, delta={candidate.basefold.delta:.6f}, "
            f"rounds={candidate.basefold_rounds}"
        ),
        "  era stages:",
    ]
    for idx, era in enumerate(candidate.era_path):
        era_rate = 1.0 / era.inv_rate
        lines.append(
            f"    stage {idx}: k=2^{era.log_k}, r={era.r}, inv_rate={era.inv_rate:.6f}, "
            f"rate={era_rate:.6f}, delta={era.delta:.6f}, log_block_length={era.log_block_length:.6f}"
        )
    lines.append("  codeswitch contributions:")
    for idx, contrib in enumerate(codeswitch_contribs, start=1):
        lines.append(
            f"    codeswitch {idx}: field_elements={contrib.field_elements:.3f}, "
            f"hashes={contrib.hashes}, oracle_length={contrib.oracle_length}"
        )
    lines.append(
        f"  basefold IOPP contribution: field_elements={basefold_contrib.field_elements:.3f}, "
        f"hashes={basefold_contrib.hashes}, oracle_length={basefold_contrib.oracle_length}, "
        f"queries={basefold_contrib.queries}, rounds={basefold_contrib.rounds}"
    )
    return "\n".join(lines)


def format_baseline(baseline: BaselineResult, budget: int) -> str:
    total_kb = baseline_proof_size_kb(baseline)
    start_kb = ((baseline.starting_field_elements * LOG_FIELD_SIZE) + (baseline.starting_hashes * LOG_HASH_SIZE)) / 8 / 1000
    start_share = 100.0 * start_kb / total_kb
    basefold_rate = 1.0 / baseline.basefold.c

    lines = [
        f"Oracle budget <= {format_budget_label(budget)} field elements",
        f"  baseline proof size: {total_kb:.3f} KB ({total_kb / 1000:.6f} MB)",
        f"  field elements in proof: {baseline.field_elements:.3f}",
        f"  hashes in proof: {baseline.hashes:.3f}",
        (
            "  starting IOR contribution: "
            f"field_elements={baseline.starting_field_elements:.3f}, hashes={baseline.starting_hashes}, "
            f"size={start_kb:.3f} KB ({start_share:.2f}% of proof)"
        ),
        f"  total oracle length: {baseline.total_oracle_length} (basefold only)",
        f"  eta: {baseline.eta}",
        f"  k0 exponent: {baseline.k0_exp}",
        f"  k0 value: {2**baseline.k0_exp}",
        f"  eta * k0: {baseline.eta * (2**baseline.k0_exp)}",
        (
            f"  basefold code: d={baseline.basefold.d}, c={baseline.basefold.c}, "
            f"rate={basefold_rate:.6f}, delta={baseline.basefold.delta:.6f}, "
            f"rounds={baseline.basefold_rounds}"
        ),
        (
            "  basefold IOPP contribution: "
            f"field_elements={baseline.basefold_field_elements:.3f}, "
            f"hashes={baseline.basefold_hashes}, "
            f"oracle_length={baseline.basefold_oracle_length}"
        ),
    ]
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Estimate IOPP proof size with variable codeswitch chain, "
            "explicit oracle-length accounting, and budget-constrained optimization."
        )
    )
    parser.add_argument("--start-k-exp", type=int, default=24)
    parser.add_argument(
        "--optimize-k0",
        action="store_true",
        help="Optimize k0 with eta derived from eta*k0=2^universal-message-exp and eta constrained by [eta-min-exp, eta-max-exp].",
    )
    parser.add_argument(
        "--universal-message-exp",
        type=int,
        default=30,
        help="Fix eta*k0 = 2^universal-message-exp when optimizing over k0.",
    )
    parser.add_argument("--eta-min-exp", type=int, default=4)
    parser.add_argument("--eta-max-exp", type=int, default=14)
    parser.add_argument("--min-k-exp", type=int, default=19, help="Must stay > 18.")
    parser.add_argument("--final-message-exp", type=int, default=12)
    parser.add_argument("--min-codeswitches", type=int, default=1, choices=[1, 2, 3])
    parser.add_argument("--max-codeswitches", type=int, default=3, choices=[1, 2, 3])
    parser.add_argument("--era-r-min", type=int, default=4)
    parser.add_argument("--era-r-max", type=int, default=16)
    parser.add_argument("--basefold-c-min", type=int, default=2)
    parser.add_argument("--basefold-c-max", type=int, default=16)
    parser.add_argument(
        "--conjecture",
        action="store_true",
        help="If set, use eps=delta everywhere instead of eps=1-(1-delta)^(1/3).",
    )
    parser.add_argument(
        "--distance-table-path",
        type=Path,
        default=Path("precomputed_distances.txt"),
    )
    parser.add_argument(
        "--optimization-output-path",
        type=Path,
        default=Path("iopp_optimization_results.txt"),
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if not args.optimize_k0 and args.start_k_exp <= args.min_k_exp:
        raise ValueError("start-k-exp must be strictly larger than min-k-exp")
    if args.eta_min_exp > args.eta_max_exp:
        raise ValueError("eta-min-exp must be <= eta-max-exp")
    if args.eta_min_exp < 0:
        raise ValueError("eta-min-exp must be non-negative")
    if not args.optimize_k0 and args.start_k_exp > args.universal_message_exp:
        raise ValueError("start-k-exp must be <= universal-message-exp")
    if args.min_k_exp <= 18:
        raise ValueError("min-k-exp must be > 18")
    if args.final_message_exp >= args.min_k_exp:
        raise ValueError("final-message-exp must be below all k_i exponents")
    if args.min_codeswitches > args.max_codeswitches:
        raise ValueError("min-codeswitches must be <= max-codeswitches")
    if not power_of_two_values(args.basefold_c_min, args.basefold_c_max):
        raise ValueError("basefold c range has no powers of two")
    start_k_eta_pairs = candidate_start_k_eta_pairs(args)
    if not start_k_eta_pairs:
        raise ValueError(
            "No feasible (k0, eta) candidates from eta range and message-size constraints"
        )

    era_table, basefold_table = get_or_build_distance_tables(args)
    universal_message_size = 2**args.universal_message_exp
    base_budget_float = universal_message_size * (ERA_BLOCK_INV_RATE_HINT * FIXED_ERA_STAGE0_R)
    derived_budget_float = BUDGET_SCALE * base_budget_float
    derived_budget = int(derived_budget_float)
    budgets = [derived_budget]

    lines: list[str] = []
    lines.append(f"Distance table written to: {args.distance_table_path}")
    lines.append(f"Precomputed ERA entries: {len(era_table)}")
    lines.append(f"Precomputed Basefold entries: {len(basefold_table)}")
    lines.append(f"Fixed ERA stage 0 repetition: r={FIXED_ERA_STAGE0_R}")
    lines.append(f"Conjecture mode: {'ON (eps=delta)' if args.conjecture else 'OFF'}")
    lines.append(
        f"Eta exponent range: [{args.eta_min_exp}, {args.eta_max_exp}] "
        f"(eta in [2^{args.eta_min_exp}, 2^{args.eta_max_exp}])"
    )
    lines.append(
        "Feasible (k0_exp, eta_exp) pairs: "
        + ", ".join(
            f"({k_exp}, {int(math.log2(eta))})"
            for k_exp, eta in start_k_eta_pairs
        )
    )
    lines.append(
        f"k0 optimization: {'ON' if args.optimize_k0 else 'OFF'} "
        f"(constraint eta*k0 = 2^{args.universal_message_exp})"
    )
    lines.append(
        "Derived oracle budget = budget_scale * (eta*k0) * era0_inv_rate = "
        f"{BUDGET_SCALE:.3f} * {universal_message_size} * "
        f"{(ERA_BLOCK_INV_RATE_HINT * FIXED_ERA_STAGE0_R):.6f} "
        f"= {derived_budget_float:.3f} (using floor -> {derived_budget})"
    )

    best_by_budget, per_codeswitch = optimize(
        args,
        era_table,
        basefold_table,
        budgets,
        conjecture=args.conjecture,
    )
    baseline_by_budget: dict[int, BaselineResult | None] = {
        budget: optimize_baseline(
            args=args,
            basefold_table=basefold_table,
            budget=budget,
            conjecture=args.conjecture,
        )
        for budget in budgets
    }

    lines.append("")
    lines.append("=== Optimization Results ===")
    for budget in budgets:
        best = best_by_budget[budget]
        if best is None:
            lines.append(
                f"Oracle budget <= {format_budget_label(budget)}: no feasible configuration found"
            )
            continue
        lines.append(format_candidate(best, budget, args.conjecture))
        lines.append("")

    lines.append("=== Baseline (No Codeswitch) ===")
    for budget in budgets:
        baseline = baseline_by_budget[budget]
        if baseline is None:
            lines.append(
                f"Oracle budget <= {format_budget_label(budget)}: no feasible baseline found"
            )
            continue
        lines.append(format_baseline(baseline, budget))
        lines.append("")

    lines.append("=== Best Params By Codeswitch Count ===")
    for target_budget in budgets:
        lines.append(f"Oracle budget <= {format_budget_label(target_budget)} field elements")
        for num_codeswitches in [1, 2, 3]:
            if not (args.min_codeswitches <= num_codeswitches <= args.max_codeswitches):
                lines.append(f"  codeswitches={num_codeswitches}: skipped by current CLI range")
                continue
            best = per_codeswitch[num_codeswitches][target_budget]
            if best is None:
                lines.append(
                    "  "
                    f"codeswitches={num_codeswitches}: no feasible configuration under "
                    f"{format_budget_label(target_budget)} oracle-length budget"
                )
                continue
            lines.append(
                f"  codeswitches={num_codeswitches}: "
                f"proof={candidate_proof_size_kb(best):.3f} KB, "
                f"oracle={best.total_oracle_length}"
            )
        lines.append("")

    output_text = "\n".join(lines).rstrip() + "\n"
    print(output_text, end="")

    args.optimization_output_path.parent.mkdir(parents=True, exist_ok=True)
    with args.optimization_output_path.open("w", encoding="ascii") as handle:
        handle.write(output_text)
    print(f"Optimization output written to: {args.optimization_output_path}")


if __name__ == "__main__":
    main()
