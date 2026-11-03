# The ranked count: why pairwise margins, and not instant runoff

isoloir's `ranked` kind lets a voter rank up to `depth` candidates. This
document says how such a poll is counted, what the count guarantees,
why that count was chosen, and how it compares to the method most people
mean by "ranked choice voting", instant runoff (IRV). The normative text
is [SPEC.md §7.1](../SPEC.md) (the kind) and §9 (the ballot); the
present document explains.

In one line: **a ranked poll is counted by the Condorcet rule on summed
pairwise margins, never by rounds of elimination.** The two methods take
the same ballot and give different winners.

## 1. What a ballot is, what is summed

A ballot ranks up to `depth` (today 3) distinct slots out of the poll's
`M` (candidates, then the blank if the poll has one). The circuit proves
the ballot well-formed and turns it into a vector of small integers, the
ballot's **values**. The tally is the sum of these vectors, nothing else:
the authority decrypts sums, never a ballot (DESIGN §1.3).

| Values | Count | Meaning |
|---|---|---|
| `first[c]` | M | 1 for the slot ranked first |
| `ranked[c]` | M | 1 for every ranked slot |
| `margin[i<j]` | M(M−1)/2 | +1 if i is ranked before j, −1 if after, 0 if neither is ranked |

A ranked slot is before every unranked one. Unranked slots are equal to
each other (margin 0). The blank, if picked, is ranked last: it says
"these, and none of the others", and it beats every candidate left
unranked.

Summed over the ballots, `margin[i][j] > 0` means more voters put i
before j than j before i: **i beats j head to head**. The matrix of
these sums is the whole count; everything below is read from it.

## 2. How the result is read

1. **Condorcet winner.** A slot that beats every other slot head to head.
   When one exists it is the result, and it is unique. The library
   publishes it as `condorcet` in a ranked poll's results (with the
   `margins` matrix, the first choices and the ranked counts).
2. **No Condorcet winner.** Head-to-head preferences can cycle (A beats
   B, B beats C, C beats A). Then `condorcet` is null and the reader
   orders the slots by a completion rule. The reference client orders
   by the number of head-to-head wins (Copeland), then by ranked count,
   then by first choices; see §6 for better completions. A cycle is
   rare with a handful of serious candidates and is itself information:
   there is no majority preference.
3. **First choices** are published alongside, so a poll shows two
   readings side by side: whom a plurality puts first, and whom a
   majority prefers to each of the others. When they differ, that
   difference is the point of ranking.

## 3. Guarantees

Properties of the Condorcet count, by social-choice name, and what each
means for a voter.

- **Condorcet criterion.** If a majority prefers X to every rival, X
  wins. Head-to-head preference is the strongest meaning of "a majority
  prefers": no other method has a better claim to it.
- **Monotonicity.** Ranking a candidate higher never hurts that
  candidate. Ranking them lower never helps them.
- **No center squeeze.** A candidate ranked second by nearly everyone is
  not discarded for having few first places; it is exactly the kind of
  candidate the margins are made to find.
- **Independence of clones, in the common case.** Two near-identical
  candidates do not split a vote: voters who rank one before the other
  still rank both above the rest, so neither suffers for the other's
  presence. (Copeland can be affected by clones in cycles; the methods
  of §6 are not.)
- **Summable.** The count is a sum of ballot vectors, so it is
  recomputable by anyone from the published sums (DESIGN §1.4), it can
  be published as it runs (open results), it can be corrected by a
  delta ballot (new − old is a valid vector), and no individual ballot
  ever has to be decrypted. This property is what makes the method fit
  isoloir at all; see §5.
- **Participation, in the common case.** Casting a sincere ballot cannot
  make the outcome worse for you when a Condorcet winner exists before
  and after. (No Condorcet method satisfies participation in every
  cycle; none does.)

What is **not** guaranteed, honestly:

- **Strategy-proofness.** No ranked method is strategy-proof
  (Gibbard–Satterthwaite). What remains here is *burying*: ranking a
  strong rival last to manufacture a cycle. It needs coordination, a
  near-cycle, and a reader who resolves cycles weakly. Ranked Pairs and
  Schulze (§6) raise its cost.
- **Later-no-harm.** Ranking a second choice can help that second
  choice beat your first in a close pair. The flip side of having no
  center squeeze; the two properties are incompatible, and isoloir
  chooses the Condorcet side.
- **Preferences below `depth`.** A voter's 4th-to-Mth candidates count
  as equal. See §7.

## 4. Compared to instant runoff (IRV)

IRV counts the same ranked ballot by rounds: count first choices,
eliminate the last, transfer its ballots to their next choice, repeat
until someone has a majority of the remaining ballots. It is what
"ranked choice voting" means in most public debate, and it has
documented pathologies that the Condorcet count does not.

| | Condorcet on margins (isoloir) | IRV |
|---|---|---|
| Elects the candidate a majority prefers to each other | always | no (center squeeze) |
| Ranking X higher can make X lose | never | yes (non-monotonic) |
| A broadly acceptable 2nd choice can be eliminated for having few 1st places | no | yes |
| Honest first choice is safe | yes | no: ranking a frontrunner first is often the better play |
| Spoilers | none in the common case | yes, a third candidate can flip the result |
| Count is a sum (recountable from totals, homomorphic, open results, corrections) | yes | no: sequential, needs every ballot |
| Needs ballots in clear, or a multi-round decryption | no | yes |
| Explaining the result | "X beat each of the others" | "X won in round 4 after transfers" |

Two real elections show the failures:

- **Burlington, Vermont, 2009 (mayor).** Montroll beat each of the two
  others head to head: the Condorcet winner. He had the fewest first
  places of the three and was eliminated; Kiss won the IRV count. The
  city repealed IRV the next year.
- **Alaska, 2022 (US House special).** Begich beat both Palin and
  Peltola head to head. He was eliminated first, and Peltola won.
  Had a few thousand Palin voters ranked Palin *lower*, Begich would
  have won: raising a candidate hurt her supporters' outcome.

A Condorcet count on the same ballots elects Montroll and Begich. The
pathology is not the ranked ballot; it is the elimination rule, which
looks only at first places when discarding a candidate.

For isoloir the summability row decides on its own. An IRV tally has to
see each ballot to transfer it, round after round. Under encryption that
means either decrypting every ballot (the protocol's ballot secrecy is
"sums, not ballots", DESIGN §1.3) or a multi-party computation of the
elimination logic with intermediate tallies revealed. Open results and
delta corrections would be impossible. The Condorcet count needs none of
that: a margin matrix is a vector, and vectors add.

## 5. Compared to the other methods

| Method | Ballot | Summable | Main weakness | Why not here |
|---|---|---|---|---|
| Plurality (one choice) | pick one | yes | spoilers, vote splitting | it is the `choice` kind; fine for yes/no, poor for 12 candidates |
| Two-round | pick one, twice | yes | center squeeze, two polls | the official system; nothing to add by copying it |
| Borda | rank all, points by place | yes | clones: a party gains by running two candidates | manipulable by nomination |
| Approval | tick any | yes | no intensity, no order | summable and simple; weaker than margins, loses the ranking |
| Score | 0–5 per candidate | yes | strategic min/max collapses to approval | a valid alternative; a bigger circuit per slot |
| STAR | score, then top-two runoff | yes (scores + pairwise) | runoff only between two | a valid alternative; its runoff is a pairwise margin, the same primitive |
| IRV | rank | **no** | §4 | §4 |
| Condorcet (Ranked Pairs, Schulze, Minimax, Copeland) | rank | yes | cycles need a completion rule | **chosen**; the completions differ only in cycles |

Score and STAR are the serious alternatives, with similar guarantees
and a different ballot ("how much" rather than "in which order"). The
ranking was kept because it asks less of a voter facing a dozen names
and because the Condorcet reading has the plainest sentence to show:
preferred to every other candidate by a majority.

## 6. Completions, when there is no Condorcet winner

The margins fix the head-to-head results; a completion rule decides
what to do with a cycle. All of them are read from the same published
matrix, so switching is a change of the reader, not of the circuit, the
ballot or the log.

| Rule | Idea | Property |
|---|---|---|
| Copeland | most head-to-head wins | simple; many ties, clone-sensitive |
| Minimax | smallest worst defeat | simple; not clone-proof |
| Ranked Pairs (Tideman) | lock pairs by margin, skip those that make a cycle | clone-proof, monotonic, resolves ties finely |
| Schulze | strongest beatpaths | clone-proof, monotonic; the most used in practice |
| Smith//X | restrict to the Smith set, then apply X | makes any X respect the Smith set |

The reference client uses Copeland for display. A deployment that
expects contested cycles should read the matrix with Ranked Pairs or
Schulze, which the matrix supports as is.

## 7. The depth of a ranking

`depth` is how many slots a ballot may rank; a voter ranks fewer if they
like. Everything a voter did not rank is tied at the bottom, so the
count knows nothing of their order among the unranked. With `depth` 3
and 12 candidates, a voter's preferences among their 4th to 12th are
lost, and a candidate everyone ranks 4th gets no margin against the
others.

How much that matters depends on where the real contest is. If the
decisive head-to-head pair is one most voters have ranked, truncation
is harmless. If it is a pair most voters left unranked, the margin
between them comes only from the few who ranked one of the two. In a
field where the top four or five gather the bulk of first choices (the
usual shape of a presidential first round), a depth of 5 captures
nearly every decisive pair; 3 is tight in a fragmented field; 12 asks
voters to order candidates they have no opinion on and adds noise, not
information.

Cost of a deeper ranking: the margins already cover every pair of the
`M` slots, so the number of values and the size of the sums do not
change with `depth`. Only the private witness (the ranked slots) and
the well-formedness checks grow, linearly in `depth`. The circuits are
compiled with the depth as a constant (`K` in `circuits/gen.py`).

What a reader should show, whatever the depth: the number of ranked
slots is the voter's, so "preferred by a majority" is to be read as
"among the candidates the voters ranked". Publishing `ranked[c]` next to
the margins gives that denominator.

## 8. Summary of the choice

- The ballot is a ranking because twelve names call for more than one
  tick, and a ranking is a question a voter can answer.
- The count is Condorcet because it is the one reading of a ranking that
  elects the candidate a majority prefers to each of the others, never
  punishes a voter for ranking a candidate higher, and is immune to the
  centre-squeeze and spoiler failures that make IRV a poor
  recommendation.
- The count is a sum of margins because isoloir decrypts sums, never
  ballots; IRV cannot be counted that way.
- Cycles are resolved by the reader from the published matrix, so the
  completion rule can improve without touching a ballot or a proof.
