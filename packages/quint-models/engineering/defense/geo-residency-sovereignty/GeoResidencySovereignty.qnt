// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.defense.geo-residency-sovereignty
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=10
// @countermodel require-target-region-allowed step=stepSanctionedRegion max-steps=6 itf="h.sanctionedPlacementViolations > 0"
// @countermodel require-inference-region-allowed step=stepInferenceEscape max-steps=6 itf="h.inferenceEscapeViolations > 0"
// @countermodel require-cross-border-permit-if-needed step=stepUnpermittedEgress max-steps=6 itf="h.unpermittedEgressViolations > 0"
// Limits: Bounded regional residency and transfer-permit abstraction; arbitrary jurisdiction allowlists, sanctioned sets, revoked authorities, and anti-P4 intra-region sufficiency are proved unboundedly in GeoResidencyAndSovereignty.lean.
module geo_residency_sovereignty {
  type State = { targetRegionAllowed: bool, inferenceRegionAllowed: bool, crossBorderTransfer: bool, transferPermitValid: bool, admittedPlacements: int, sanctionedPlacementViolations: int, inferenceEscapeViolations: int, unpermittedEgressViolations: int }
  var h: State
  action init = h' = { targetRegionAllowed: false, inferenceRegionAllowed: false, crossBorderTransfer: false, transferPermitValid: false, admittedPlacements: 0, sanctionedPlacementViolations: 0, inferenceEscapeViolations: 0, unpermittedEgressViolations: 0 }
  action allowTargetRegion = if (not(h.targetRegionAllowed)) h' = h.with("targetRegionAllowed", true) else h' = h
  action allowInferenceRegion = if (not(h.inferenceRegionAllowed)) h' = h.with("inferenceRegionAllowed", true) else h' = h
  action markCrossBorderTransfer = if (not(h.crossBorderTransfer)) h' = h.with("crossBorderTransfer", true) else h' = h
  action issueCrossBorderPermit = if ((h.crossBorderTransfer and not(h.transferPermitValid))) h' = h.with("transferPermitValid", true) else h' = h
  action admitGeoPlacement = if ((h.admittedPlacements < 2 and h.targetRegionAllowed and h.inferenceRegionAllowed and (not(h.crossBorderTransfer) or h.transferPermitValid))) h' = h.with("admittedPlacements", (h.admittedPlacements + 1)).with("sanctionedPlacementViolations", if (h.targetRegionAllowed) h.sanctionedPlacementViolations else (h.sanctionedPlacementViolations + 1)).with("inferenceEscapeViolations", if (h.inferenceRegionAllowed) h.inferenceEscapeViolations else (h.inferenceEscapeViolations + 1)).with("unpermittedEgressViolations", if ((not(h.crossBorderTransfer) or h.transferPermitValid)) h.unpermittedEgressViolations else (h.unpermittedEgressViolations + 1)) else h' = h
  action step = any { allowTargetRegion, allowInferenceRegion, markCrossBorderTransfer, issueCrossBorderPermit, admitGeoPlacement }
  val safety = (h.sanctionedPlacementViolations == 0 and h.inferenceEscapeViolations == 0 and h.unpermittedEgressViolations == 0)
  // Countermodel engineering.defense.geo-residency-sovereignty.sanctioned-region (dropped guard: require-target-region-allowed)
  action admitPlacementSanctioned = if ((h.admittedPlacements < 2 and true and h.inferenceRegionAllowed and (not(h.crossBorderTransfer) or h.transferPermitValid))) h' = h.with("admittedPlacements", (h.admittedPlacements + 1)).with("sanctionedPlacementViolations", if (h.targetRegionAllowed) h.sanctionedPlacementViolations else (h.sanctionedPlacementViolations + 1)).with("inferenceEscapeViolations", if (h.inferenceRegionAllowed) h.inferenceEscapeViolations else (h.inferenceEscapeViolations + 1)).with("unpermittedEgressViolations", if ((not(h.crossBorderTransfer) or h.transferPermitValid)) h.unpermittedEgressViolations else (h.unpermittedEgressViolations + 1)) else h' = h
  action stepSanctionedRegion = any { step, admitPlacementSanctioned }
  // Countermodel engineering.defense.geo-residency-sovereignty.inference-escape (dropped guard: require-inference-region-allowed)
  action admitPlacementInfEscape = if ((h.admittedPlacements < 2 and h.targetRegionAllowed and true and (not(h.crossBorderTransfer) or h.transferPermitValid))) h' = h.with("admittedPlacements", (h.admittedPlacements + 1)).with("sanctionedPlacementViolations", if (h.targetRegionAllowed) h.sanctionedPlacementViolations else (h.sanctionedPlacementViolations + 1)).with("inferenceEscapeViolations", if (h.inferenceRegionAllowed) h.inferenceEscapeViolations else (h.inferenceEscapeViolations + 1)).with("unpermittedEgressViolations", if ((not(h.crossBorderTransfer) or h.transferPermitValid)) h.unpermittedEgressViolations else (h.unpermittedEgressViolations + 1)) else h' = h
  action stepInferenceEscape = any { step, admitPlacementInfEscape }
  // Countermodel engineering.defense.geo-residency-sovereignty.unpermitted-egress (dropped guard: require-cross-border-permit-if-needed)
  action admitPlacementNoPermit = if ((h.admittedPlacements < 2 and h.targetRegionAllowed and h.inferenceRegionAllowed and true)) h' = h.with("admittedPlacements", (h.admittedPlacements + 1)).with("sanctionedPlacementViolations", if (h.targetRegionAllowed) h.sanctionedPlacementViolations else (h.sanctionedPlacementViolations + 1)).with("inferenceEscapeViolations", if (h.inferenceRegionAllowed) h.inferenceEscapeViolations else (h.inferenceEscapeViolations + 1)).with("unpermittedEgressViolations", if ((not(h.crossBorderTransfer) or h.transferPermitValid)) h.unpermittedEgressViolations else (h.unpermittedEgressViolations + 1)) else h' = h
  action stepUnpermittedEgress = any { step, admitPlacementNoPermit }
  run cleanGeoPlacementTest = init.then(allowTargetRegion).then(allowInferenceRegion).then(markCrossBorderTransfer).then(issueCrossBorderPermit).then(admitGeoPlacement).then(all { assert(safety), assert(h.admittedPlacements == 1), h' = h })
  run sanctionedTargetViolatesSafetyTest = init.then(allowInferenceRegion).then(admitPlacementSanctioned).then(all { assert(not(safety)), assert(h.sanctionedPlacementViolations > 0), h' = h })
  run inferenceEscapeViolatesSafetyTest = init.then(allowTargetRegion).then(admitPlacementInfEscape).then(all { assert(not(safety)), assert(h.inferenceEscapeViolations > 0), h' = h })
  run unpermittedEgressViolatesSafetyTest = init.then(allowTargetRegion).then(allowInferenceRegion).then(markCrossBorderTransfer).then(admitPlacementNoPermit).then(all { assert(not(safety)), assert(h.unpermittedEgressViolations > 0), h' = h })
}
