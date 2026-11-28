// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

// Generated from the ProjectFormation ASCENT result; design-only module projection.
// Model context and companion catalog are selected in project_layout.
package 'DeterministicEngineering' {
    private import 'RepositoryOrganization'::*;
    doc /* Project 'DE-CASE-01'; declared intent 'reusable-library'; structural candidate 'LIB-C01'. Design assertions only; runtime capability gates remain separate. */
    part <'DE-PROJECT'> 'libraryProject' {
        part 'definitions' : 'RepositoryOrganization'::LibraryDefinitions;
        part 'documentation' : 'RepositoryOrganization'::DocumentOrganization;
        part 'methodContracts' : 'RepositoryOrganization'::MethodContracts;
        part 'projectEntry' : 'RepositoryOrganization'::ProjectEntry;
        part 'reasoning' : 'RepositoryOrganization'::ApplicationReasoning;
        part 'receiptIssuance' : 'RepositoryOrganization'::ReceiptBoundary;
        part 'review' : 'RepositoryOrganization'::ReviewBoundary;
        part 'scenarioUse' : 'RepositoryOrganization'::ProjectScenario;
        part 'selection' : 'RepositoryOrganization'::IndependentProfile;
    }
    dependency 'capture-definitions' from 'libraryProject'::'scenarioUse' to 'libraryProject'::'definitions';
    dependency 'capture-selection' from 'libraryProject'::'scenarioUse' to 'libraryProject'::'selection';
    dependency 'documentation-definitions' from 'libraryProject'::'documentation' to 'libraryProject'::'definitions';
    dependency 'entry-capture' from 'libraryProject'::'projectEntry' to 'libraryProject'::'scenarioUse';
    dependency 'entry-definitions' from 'libraryProject'::'projectEntry' to 'libraryProject'::'definitions';
    dependency 'entry-reasoning' from 'libraryProject'::'projectEntry' to 'libraryProject'::'reasoning';
    dependency 'methods-definitions' from 'libraryProject'::'methodContracts' to 'libraryProject'::'definitions';
    dependency 'reasoning-capture' from 'libraryProject'::'reasoning' to 'libraryProject'::'scenarioUse';
    dependency 'receipts-capture' from 'libraryProject'::'receiptIssuance' to 'libraryProject'::'scenarioUse';
    dependency 'review-reasoning' from 'libraryProject'::'review' to 'libraryProject'::'reasoning';
    dependency 'selection-definitions' from 'libraryProject'::'selection' to 'libraryProject'::'definitions';
    dependency 'source-definitions' from 'libraryProject'::'definitions' to 'RepositoryOrganization'::LibraryDefinitions;
    dependency 'source-documentation' from 'libraryProject'::'documentation' to 'RepositoryOrganization'::DocumentOrganization;
    dependency 'source-methodContracts' from 'libraryProject'::'methodContracts' to 'RepositoryOrganization'::MethodContracts;
    dependency 'source-projectEntry' from 'libraryProject'::'projectEntry' to 'RepositoryOrganization'::ProjectEntry;
    dependency 'source-reasoning' from 'libraryProject'::'reasoning' to 'RepositoryOrganization'::ApplicationReasoning;
    dependency 'source-receiptIssuance' from 'libraryProject'::'receiptIssuance' to 'RepositoryOrganization'::ReceiptBoundary;
    dependency 'source-review' from 'libraryProject'::'review' to 'RepositoryOrganization'::ReviewBoundary;
    dependency 'source-scenarioUse' from 'libraryProject'::'scenarioUse' to 'RepositoryOrganization'::ProjectScenario;
    dependency 'source-selection' from 'libraryProject'::'selection' to 'RepositoryOrganization'::IndependentProfile;
    part 'requiredProducts' {
        part 'D01';
        part 'D02';
        part 'D03';
        part 'D04';
        part 'D05';
        part 'D06';
        part 'D07';
        part 'D08';
        part 'D09';
        part 'D10';
    }
    part 'requiredDuties' {
        part 'DE-O-ARCH';
        part 'DE-O-DEC';
        part 'DE-O-DOC';
        part 'DE-O-REVIEW';
        part 'DE-O-TRACE';
    }
    part openCapabilities {
        part 'authority';
        part 'capture-origin';
        part 'method-validation';
        part 'source-load';
    }
    part 'placements' {
        part 'agentDefenseAudit' : 'RepositoryOrganization'::'DistributionPackage';
        part 'documents' : 'RepositoryOrganization'::'DocumentItem';
        part 'examples' : 'RepositoryOrganization'::'UserExample';
        part 'infrastructure' : 'RepositoryOrganization'::'PackageInfrastructure';
        part 'languageAssets' : 'RepositoryOrganization'::'LanguageAssets';
        part 'library' : 'RepositoryOrganization'::'SchemeModule';
        part 'projects' : 'RepositoryOrganization'::'ProjectEntry';
        part 'quintModels' : 'RepositoryOrganization'::'DistributionPackage';
        part 'quintModulesResolver' : 'RepositoryOrganization'::'DistributionPackage';
        part 'render' : 'RepositoryOrganization'::'DistributionPackage';
        part 'tests' : 'RepositoryOrganization'::'DevelopmentVerification';
        part 'views' : 'RepositoryOrganization'::'ArchitectureView';
    }
}
