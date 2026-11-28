// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

package DeterministicEngineeringRepository {
    public import ScalarValues::*;

    abstract part def Placement {
        attribute pathPattern : String;
        attribute ecosystem : String;
        attribute roles : String;
        attribute rejects : String;
    }

    part def SchemeModule :> Placement;
    part def LanguageAssets :> Placement;
    part def DistributionPackage :> Placement {
        attribute packageName : String;
        attribute family : String;
        attribute mirror : String;
    }
    part def ProjectEntry :> Placement;
    part def UserExample :> Placement;
    part def DevelopmentVerification :> Placement;
    part def DocumentItem :> Placement;
    part def ArchitectureView :> Placement;
    part def PackageInfrastructure :> Placement;

    part repository {
        part library : SchemeModule {
            attribute redefines pathPattern = "library/<module>/";
            attribute redefines ecosystem = "gerbil yuanxu";
            attribute redefines roles = "definitions method-contracts selection reasoning";
            attribute redefines rejects = "execution typescript other-language-sources generated-output";
        }
        part languageAssets : LanguageAssets {
            attribute redefines pathPattern = "languages-engineering/<lang>/<domain>/<subject>/";
            attribute redefines ecosystem = "native-toolchain";
            attribute redefines roles = "checked-subjects";
            attribute redefines rejects = "scheme-declarations execution-results";
        }
        part render : DistributionPackage {
            attribute redefines pathPattern = "packages/render/";
            attribute redefines ecosystem = "bun";
            attribute redefines roles = "presentation";
            attribute redefines rejects = "verification-models quint-content check-plans";
            attribute redefines packageName = "@deterministic-engineering/render";
            attribute redefines family = "presentation";
            attribute redefines mirror = "hardenedlinux/deterministic-engineering-render";
        }
        part quintModels : DistributionPackage {
            attribute redefines pathPattern = "packages/quint-models/<domain>/<subdomain>/<model>/";
            attribute redefines ecosystem = "bun,gerbil-yuanxu";
            attribute redefines roles = "quint-model-content,co-located-yuanxu-declarations,model-readmes";
            attribute redefines rejects = "tool-code rendering json-sidecars relative-cross-module-imports orphan-qnt";
            attribute redefines packageName = "@deterministic-engineering/quint-models";
            attribute redefines family = "quint-model-content";
            attribute redefines mirror = "hardenedlinux/deterministic-engineering-quint-models";
        }
        part quintModulesResolver : DistributionPackage {
            attribute redefines pathPattern = "packages/quint-modules-resolver/";
            attribute redefines ecosystem = "bun";
            attribute redefines roles = "verification-tooling";
            attribute redefines rejects = "model-content quint-redistribution";
            attribute redefines packageName = "@deterministic-engineering/quint-modules-resolver";
            attribute redefines family = "verification-tooling";
            attribute redefines mirror = "hardenedlinux/deterministic-engineering-quint-modules-resolver";
        }
        part projects : ProjectEntry {
            attribute redefines pathPattern = "projects/<project>/";
            attribute redefines roles = "project-entry";
        }
        part examples : UserExample {
            attribute redefines pathPattern = "examples/";
            attribute redefines roles = "user-settings";
        }
        part tests : DevelopmentVerification {
            attribute redefines pathPattern = "t/ t/yanxu/<Mount>/<owner>/";
            attribute redefines roles = "tool-execution independent-gold evidence-registration";
        }
        part documents : DocumentItem {
            attribute redefines pathPattern = "docs/<area>/<category>/<JD>-*.org";
            attribute redefines roles = "documentation";
        }
        part views : ArchitectureView {
            attribute redefines pathPattern = "docs/90-99-views/90-architecture-views/90.<n>-*";
            attribute redefines roles = "documentation-projection";
        }
        part infrastructure : PackageInfrastructure {
            attribute redefines pathPattern = "gerbil.pkg init.ss build.ss types.ss config.ss Justfile package.json";
            attribute redefines roles = "multi-window-selection build-entry shared-vocabulary";
        }
    }

    dependency from repository.quintModels to repository.library;
    dependency from repository.quintModulesResolver to repository.quintModels;
    dependency from repository.views to repository.render;
    dependency from repository.tests to repository.library;
    dependency from repository.tests to repository.quintModels;
    dependency from repository.projects to repository.library;

    // Organization declaration only. It establishes no package publication,
    // mirror, rule result, build acceptance or application authority.
}
