// Generated from the ProjectFormation ASCENT result; design-only module projection.
// Model context and companion catalog are selected in project_layout.
package 'DeterministicEngineering' {
    private import 'DECaseOrganization'::*;
    doc /* Project 'DE-CASE-01'; confirmed intent 'reusable-library'; structural candidate 'LIB-C01'. Design assertions only; runtime capability gates remain separate. */
    part def 'LibraryDefinitions';
    part def 'DocumentOrganization';
    part def 'MethodContracts';
    part def 'ProjectEntry';
    part def 'ApplicationReasoning';
    part def 'ReceiptBoundary';
    part def 'ReviewBoundary';
    part def 'ProjectScenario';
    part def 'IndependentProfile';
    part <'DE-PROJECT'> 'libraryProject' {
        part 'definitions' : 'LibraryDefinitions';
        part 'documentation' : 'DocumentOrganization';
        part 'methodContracts' : 'MethodContracts';
        part 'projectEntry' : 'ProjectEntry';
        part 'reasoning' : 'ApplicationReasoning';
        part 'receiptIssuance' : 'ReceiptBoundary';
        part 'review' : 'ReviewBoundary';
        part 'scenarioUse' : 'ProjectScenario';
        part 'selection' : 'IndependentProfile';
    }
    dependency edge0 from 'libraryProject'::'documentation' to 'libraryProject'::'definitions';
    dependency edge1 from 'libraryProject'::'methodContracts' to 'libraryProject'::'definitions';
    dependency edge2 from 'libraryProject'::'projectEntry' to 'libraryProject'::'definitions';
    dependency edge3 from 'libraryProject'::'projectEntry' to 'libraryProject'::'reasoning';
    dependency edge4 from 'libraryProject'::'projectEntry' to 'libraryProject'::'scenarioUse';
    dependency edge5 from 'libraryProject'::'reasoning' to 'libraryProject'::'scenarioUse';
    dependency edge6 from 'libraryProject'::'receiptIssuance' to 'libraryProject'::'scenarioUse';
    dependency edge7 from 'libraryProject'::'review' to 'libraryProject'::'reasoning';
    dependency edge8 from 'libraryProject'::'scenarioUse' to 'libraryProject'::'definitions';
    dependency edge9 from 'libraryProject'::'scenarioUse' to 'libraryProject'::'selection';
    dependency edge10 from 'libraryProject'::'selection' to 'libraryProject'::'definitions';
    dependency source0 from 'libraryProject'::'definitions' to 'DECaseOrganization'::actual::projectFormation::organizationLibrary;
    dependency source1 from 'libraryProject'::'documentation' to 'DECaseOrganization'::products::architecture;
    dependency source2 from 'libraryProject'::'methodContracts' to 'DECaseOrganization'::actual::methods;
    dependency source3 from 'libraryProject'::'projectEntry' to 'DECaseOrganization'::actual::projectFormation::projectEntry;
    dependency source4 from 'libraryProject'::'reasoning' to 'DECaseOrganization'::actual::projectFormation::reasoning;
    dependency source5 from 'libraryProject'::'receiptIssuance' to 'DECaseOrganization'::external::yuanxu;
    dependency source6 from 'libraryProject'::'review' to 'DECaseOrganization'::actual::review;
    dependency source7 from 'libraryProject'::'scenarioUse' to 'DECaseOrganization'::actual::projectFormation::scenario;
    dependency source8 from 'libraryProject'::'selection' to 'DECaseOrganization'::actual::projectFormation::profile;
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
}
