// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.defense.search-diversity-exploration
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=10
// @countermodel require-niche-diversity step=stepModeCollapse max-steps=7 itf="h.modeCollapseViolations > 0"
// @countermodel require-backtrack-on-deadend step=stepDeadEndLoop max-steps=7 itf="h.deadEndLoopViolations > 0"
// @countermodel require-witness-before-promote step=stepUngroundedPromotion max-steps=7 itf="h.ungroundedPromotionViolations > 0"
// @countermodel require-bounded-frontier step=stepFrontierExplosion max-steps=7 itf="h.frontierExplosionViolations > 0"
// Limits: Finite 2-niche bounded-frontier abstraction of Quality-Diversity (MAP-Elites / MMR), SWE-Search / LATS dead-end backtracking, grounded witness admission, and Dusa bounded choice branching; full multi-file code graphs and continuous DPP/MMR scoring execute in library/search-engine and Marlin's live Search DSL runtime.
module search_diversity_exploration {
  type State = {
    maxFrontier: int,
    activeFrontier: int,
    nicheACount: int,
    nicheBCount: int,
    currentNiche: int,
    currentDeadEnd: bool,
    witnessVerified: bool,
    promotedFindings: int,
    modeCollapseViolations: int,
    deadEndLoopViolations: int,
    ungroundedPromotionViolations: int,
    frontierExplosionViolations: int
  }
  var h: State

  action init = h' = {
    maxFrontier: 4,
    activeFrontier: 1,
    nicheACount: 1,
    nicheBCount: 0,
    currentNiche: 1,
    currentDeadEnd: false,
    witnessVerified: false,
    promotedFindings: 0,
    modeCollapseViolations: 0,
    deadEndLoopViolations: 0,
    ungroundedPromotionViolations: 0,
    frontierExplosionViolations: 0
  }

  action markCurrentDeadEnd =
    if (not(h.currentDeadEnd))
      h' = h.with("currentDeadEnd", true)
    else h' = h

  action backtrackToAlternateNiche =
    if (h.currentDeadEnd)
      h' = h.with("currentDeadEnd", false).with("currentNiche", if (h.currentNiche == 1) 2 else 1)
    else h' = h

  action verifyCandidateWitness =
    if (not(h.witnessVerified) and not(h.currentDeadEnd))
      h' = h.with("witnessVerified", true)
    else h' = h

  action pruneFrontierBranch =
    if (h.activeFrontier > 1)
      h' = h.with("activeFrontier", h.activeFrontier - 1)
    else h' = h

  action expandDiverseNicheB =
    if (not(h.currentDeadEnd) and h.activeFrontier < h.maxFrontier)
      h' = h.with("activeFrontier", h.activeFrontier + 1)
            .with("nicheBCount", h.nicheBCount + 1)
            .with("currentNiche", 2)
    else h' = h

  action expandNicheAWithDiversityGuard =
    if (not(h.currentDeadEnd) and (h.nicheBCount > 0 or h.nicheACount < 2) and h.activeFrontier < h.maxFrontier)
      h' = h.with("activeFrontier", h.activeFrontier + 1)
            .with("nicheACount", h.nicheACount + 1)
            .with("currentNiche", 1)
            .with("modeCollapseViolations", if (h.nicheBCount > 0 or h.nicheACount < 2) h.modeCollapseViolations else h.modeCollapseViolations + 1)
            .with("deadEndLoopViolations", if (not(h.currentDeadEnd)) h.deadEndLoopViolations else h.deadEndLoopViolations + 1)
            .with("frontierExplosionViolations", if (h.activeFrontier < h.maxFrontier) h.frontierExplosionViolations else h.frontierExplosionViolations + 1)
    else h' = h

  action promoteGroundedFinding =
    if (h.witnessVerified and not(h.currentDeadEnd))
      h' = h.with("promotedFindings", h.promotedFindings + 1)
            .with("witnessVerified", false)
            .with("ungroundedPromotionViolations", if (h.witnessVerified and not(h.currentDeadEnd)) h.ungroundedPromotionViolations else h.ungroundedPromotionViolations + 1)
    else h' = h

  action step = any {
    markCurrentDeadEnd,
    backtrackToAlternateNiche,
    verifyCandidateWitness,
    pruneFrontierBranch,
    expandDiverseNicheB,
    expandNicheAWithDiversityGuard,
    promoteGroundedFinding
  }

  val safety = (
    h.modeCollapseViolations == 0 and
    h.deadEndLoopViolations == 0 and
    h.ungroundedPromotionViolations == 0 and
    h.frontierExplosionViolations == 0
  )

  // Countermodel engineering.defense.search-diversity-exploration.mode-collapse (dropped guard: require-niche-diversity)
  action expandNicheACollapsed =
    if (not(h.currentDeadEnd) and true and h.activeFrontier < h.maxFrontier)
      h' = h.with("activeFrontier", h.activeFrontier + 1)
            .with("nicheACount", h.nicheACount + 1)
            .with("currentNiche", 1)
            .with("modeCollapseViolations", if (h.nicheBCount > 0 or h.nicheACount < 2) h.modeCollapseViolations else h.modeCollapseViolations + 1)
    else h' = h
  action stepModeCollapse = any { step, expandNicheACollapsed }

  // Countermodel engineering.defense.search-diversity-exploration.deadend-loop (dropped guard: require-backtrack-on-deadend)
  action expandWithoutBacktrack =
    if (true and (h.nicheBCount > 0 or h.nicheACount < 2) and h.activeFrontier < h.maxFrontier)
      h' = h.with("activeFrontier", h.activeFrontier + 1)
            .with("deadEndLoopViolations", if (not(h.currentDeadEnd)) h.deadEndLoopViolations else h.deadEndLoopViolations + 1)
    else h' = h
  action stepDeadEndLoop = any { step, expandWithoutBacktrack }

  // Countermodel engineering.defense.search-diversity-exploration.ungrounded-promotion (dropped guard: require-witness-before-promote)
  action promoteWithoutWitness =
    if (true)
      h' = h.with("promotedFindings", h.promotedFindings + 1)
            .with("ungroundedPromotionViolations", if (h.witnessVerified and not(h.currentDeadEnd)) h.ungroundedPromotionViolations else h.ungroundedPromotionViolations + 1)
    else h' = h
  action stepUngroundedPromotion = any { step, promoteWithoutWitness }

  // Countermodel engineering.defense.search-diversity-exploration.frontier-explosion (dropped guard: require-bounded-frontier)
  action expandBeyondFrontierBound =
    if (not(h.currentDeadEnd) and h.nicheBCount > 0 and true)
      h' = h.with("activeFrontier", h.activeFrontier + 1)
            .with("frontierExplosionViolations", if (h.activeFrontier < h.maxFrontier) h.frontierExplosionViolations else h.frontierExplosionViolations + 1)
    else h' = h
  action stepFrontierExplosion = any { step, expandBeyondFrontierBound }

  run diverseBacktrackingAndGroundedPromotionTest =
    init
      .then(expandDiverseNicheB)
      .then(markCurrentDeadEnd)
      .then(backtrackToAlternateNiche)
      .then(expandNicheAWithDiversityGuard)
      .then(verifyCandidateWitness)
      .then(promoteGroundedFinding)
      .then(all {
        assert(safety),
        assert(h.nicheACount == 2),
        assert(h.nicheBCount == 1),
        assert(h.promotedFindings == 1),
        h' = h
      })

  run modeCollapseRefutedTest =
    init
      .then(expandNicheACollapsed)
      .then(expandNicheACollapsed)
      .then(all { assert(not(safety)), assert(h.modeCollapseViolations > 0), h' = h })

  run deadEndLoopRefutedTest =
    init
      .then(markCurrentDeadEnd)
      .then(expandWithoutBacktrack)
      .then(all { assert(not(safety)), assert(h.deadEndLoopViolations > 0), h' = h })

  run ungroundedPromotionRefutedTest =
    init
      .then(promoteWithoutWitness)
      .then(all { assert(not(safety)), assert(h.ungroundedPromotionViolations > 0), h' = h })

  run frontierExplosionRefutedTest =
    init
      .then(expandDiverseNicheB)
      .then(expandDiverseNicheB)
      .then(expandDiverseNicheB)
      .then(expandBeyondFrontierBound)
      .then(all { assert(not(safety)), assert(h.frontierExplosionViolations > 0), h' = h })
}
