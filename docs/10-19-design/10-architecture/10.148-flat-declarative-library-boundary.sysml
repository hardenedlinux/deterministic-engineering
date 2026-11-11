// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

package DeterministicEngineeringLibrary {
    public import ScalarValues::*;

    part def LibraryModule {
        attribute directory : String;
        attribute classification : String;
    }

    part library {
        part capacity : LibraryModule {
            attribute redefines directory = "library/bounded-capacity";
            attribute redefines classification = "domain numeric";
        }
        part lifetime : LibraryModule {
            attribute redefines directory = "library/resource-lifetime";
            attribute redefines classification = "domain memory";
        }
        part backpressure : LibraryModule {
            attribute redefines directory = "library/backpressure-memory";
            attribute redefines classification = "domain concurrency";
        }
        part tokioRayon : LibraryModule {
            attribute redefines directory = "library/backpressure-tokio-rayon";
            attribute redefines classification = "specialization rust concurrency";
        }
        part sourceContracts : LibraryModule {
            attribute redefines directory = "library/source-contracts";
            attribute redefines classification = "method verification";
        }
        part contractProfiles : LibraryModule {
            attribute redefines directory = "library/source-contract-profiles";
            attribute redefines classification = "profile source-contract";
        }
        part evidenceRules : LibraryModule {
            attribute redefines directory = "library/evidence";
            attribute redefines classification = "rule declaration";
        }
    }

    dependency from library.tokioRayon to library.backpressure;
    dependency from library.contractProfiles to library.sourceContracts;

    // This model declares Library organization. It does not define an App Server,
    // provider, scheduler, process host, operational authority or Runtime instance.
}
